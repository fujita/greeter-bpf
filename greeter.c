/*
 * Copyright (C) 2020 The greeter-bpf Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include "greeter.skel.h"
#include "trace_helpers.h"
#include <sys/select.h>

#include "greeter.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int setup_bpf(int listen_fd)
{
	struct greeter_bpf *obj;

	obj = greeter_bpf__open_and_load();

	int cg_fd = open("/sys/fs/cgroup/unified/", __O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "failed to set reuseaddr: %s\n",
			strerror(errno));
		return -1;
	}

	struct bpf_program *p =
		bpf_object__find_program_by_name(obj->obj, "_sock_ops");
	int err = bpf_prog_attach(bpf_program__fd(p), cg_fd,
				  BPF_CGROUP_SOCK_OPS, 0);
	if (err < 0) {
		fprintf(stderr, "failed to attach sockops: %s\n",
			strerror(errno));
		return -1;
	}

	// err = greeter_bpf__attach(obj);
	// if (err)
	// {
	//     fprintf(stderr, "failed to attach: %s\n",
	//             strerror(errno));
	//     return 1;
	// }

	int sockhash_fd = bpf_object__find_map_fd_by_name(obj->obj, "sockhash");
	p = bpf_object__find_program_by_name(obj->obj, "_prog_parser");
	err = bpf_prog_attach(bpf_program__fd(p), sockhash_fd,
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err < 0) {
		fprintf(stderr, "failed to attach parser: %s\n",
			strerror(errno));
		return -1;
	}
	p = bpf_object__find_program_by_name(obj->obj, "_prog_verdict");
	err = bpf_prog_attach(bpf_program__fd(p), sockhash_fd,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err < 0) {
		fprintf(stderr, "failed to attach verdict: %s\n",
			strerror(errno));
		return -1;
	}

	__u64 idx = 0;
	__u64 val = listen_fd;
	err = bpf_map_update_elem(sockhash_fd, &idx, &val, BPF_NOEXIST);
	if (err != 0) {
		fprintf(stderr, "failed to add listen sock to sockhash: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %s\n",
			strerror(errno));
		return 1;
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	int on = 1;
	err = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
			 sizeof(on));
	if (err < 0) {
		fprintf(stderr, "failed to set reuseaddr: %s\n",
			strerror(errno));
		return 1;
	}

	struct sockaddr sa;
	memset(&sa, 0, sizeof(sa));
	struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(GRPC_PORT);
	inet_aton("0.0.0.0", &sin->sin_addr);

	err = bind(listen_fd, (struct sockaddr *)sin, sizeof(*sin));
	if (err < 0) {
		fprintf(stderr, "failed to bind: %s\n", strerror(errno));
		return 1;
	}

	err = listen(listen_fd, 8192);
	if (err < 0) {
		fprintf(stderr, "failed to listen: %s\n", strerror(errno));
		return 1;
	}

	if (setup_bpf(listen_fd) < 0) {
		return -1;
	}

	printf("Hello, greeter\n");

	int epfd = epoll_create(1);
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = listen_fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

	int i, nevent;
	struct epoll_event events[1024];
retry:
	nevent = epoll_wait(epfd, events, ARRAY_SIZE(events), -1);
	for (i = 0; i < nevent; i++) {
		if (events[i].data.fd == listen_fd) {
			struct sockaddr_in ss;
			socklen_t ss_len = sizeof(struct sockaddr_in);
			int fd = accept(listen_fd, (struct sockaddr *)&ss,
					&ss_len);
			if (fd < 0) {
				continue;
			}

			// printf("accepted %d %s %d\n", fd,
			//        inet_ntoa(ss.sin_addr), ntohs(ss.sin_port));

			int on = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on,
				   sizeof(on));

			__u8 buf[] = {
				0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
			};
			int ret = write(fd, buf, ARRAY_SIZE(buf));
			if (ret != ARRAY_SIZE(buf)) {
				printf("initial socket write failed: %d\n",
				       ret);
				close(fd);
				continue;
			}

			struct epoll_event ev;
			memset(&ev, 0, sizeof(ev));
			ev.events = EPOLLRDHUP | EPOLLET;
			ev.data.fd = fd;
			epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
		} else {
			close(events[i].data.fd);
		}
	}
	goto retry;

	return 0;
}
