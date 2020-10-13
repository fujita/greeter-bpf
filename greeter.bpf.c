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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "greeter.h"

const volatile char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const volatile __u8 uncached_header1[] = { 0x88, 0x5f, 0x8b, 0x1d, 0x75,
					   0xd0, 0x62, 0x0d, 0x26, 0x3d,
					   0x4c, 0x4d, 0x65, 0x64 };

const volatile __u8 cached_header1[] = { 0x88, 0xc0 };

const volatile __u8 data_payload[] = { 0x00, 0x00, 0x00, 0x00, 0x0b, 0x0a,
				       0x09, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
				       0x20, 0x4a, 0x6f, 0x65 };

const volatile __u8 uncached_header2[] = { 0x40, 0x88, 0x9a, 0xca, 0xc8, 0xb2,
					   0x12, 0x34, 0xda, 0x8f, 0x01, 0x30,
					   0x40, 0x89, 0x9a, 0xca, 0xc8, 0xb5,
					   0x25, 0x42, 0x07, 0x31, 0x7f, 0x00 };

const volatile __u8 cached_header2[] = { 0xbf, 0xbe };

#define UNCACHED_HEADERS_FRAME1_LEN                                            \
	(FRAME_HEADER_LEN + ARRAY_SIZE(uncached_header1))

#define UNCACHED_HEADERS_FRAME2_LEN                                            \
	(FRAME_HEADER_LEN + ARRAY_SIZE(uncached_header2))

#define DATA_FRAME_LEN (FRAME_HEADER_LEN + ARRAY_SIZE(data_payload))

#define PREFACE_LEN (sizeof(preface) - 1)

#define htons(n)                                                               \
	(((((unsigned short)(n)&0xFF)) << 8) |                                 \
	 (((unsigned short)(n)&0xFF00) >> 8))

#define htonl(n)                                                               \
	(((((unsigned long)(n)&0xFF)) << 24) |                                 \
	 ((((unsigned long)(n)&0xFF00)) << 8) |                                \
	 ((((unsigned long)(n)&0xFF0000)) >> 8) |                              \
	 ((((unsigned long)(n)&0xFF000000)) >> 24))

#define FRAME_HEADER_LEN 9
#define DATA_FRAME 0
#define HEADERS_FRAME 1
#define SETTINGS_FRAME 4
#define PING_FRAME 6
#define WINDOW_UPDATE_FRAME 8

#define FLAGS_ACK 1

struct frame_header {
	__u8 length[3];
	__u8 frame_type;
	__u8 flags;
	__u32 stream_id;
} __attribute__((packed));

static u32 frame_length(struct frame_header *h)
{
	return (u32)h->length[0] << 16 | (u32)h->length[1] | h->length[2];
}

static void update_frame_header(struct frame_header *h, __u32 length,
				__u8 frame_type, __u8 flags, __u32 stream_id)
{
	h->length[0] = 0xff & length << 16;
	h->length[1] = 0xff & length << 8;
	h->length[2] = 0xff & length;
	h->frame_type = frame_type;
	h->flags = flags;
	h->stream_id = stream_id;
}

static void update_settings(struct settings *h, __u16 id, __u32 value)
{
	h->identifier = htons(id);
	h->value = htonl(value);
}

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, MAX_CLIENT);
} sockhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct client));
	__uint(max_entries, MAX_CLIENT);
} clientmap SEC(".maps");

SEC("sk_skb/stream_parser")
int _prog_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
	u64 key = ((u64)skb->remote_ip4 << 32) | skb->remote_port;
	struct client *c = bpf_map_lookup_elem(&clientmap, &key);
	if (!c) {
		bpf_printk("can't find client %u\n", key);
		return SK_DROP;
	}
	__builtin_memset(&c->rsp, 0,
			 sizeof(struct response) * ARRAY_SIZE(c->rsp));

	bpf_skb_pull_data(skb, skb->len);
	// bpf_printk("verdict %x %u", key, skb->data_end - skb->data);

	int preface_offset = 0;
	int nr_rsp = 0;
	int i;

	if (!c->established) {
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
		char *p = data;
		if ((void *)p + PREFACE_LEN > data_end) {
			bpf_printk("preface is too short %u\n",
				   data_end - data);
			return SK_DROP;
		}
		for (i = 0; i < PREFACE_LEN; i++) {
			if (preface[i] != p[i]) {
				break;
			}
		}
		if (i == PREFACE_LEN) {
			c->established = 1;
			bpf_map_update_elem(&clientmap, &key, c, BPF_EXIST);
			preface_offset = PREFACE_LEN;
		} else {
			bpf_printk("invalid preface\n");
			return SK_DROP;
		}
	}

	if (!c->established) {
		return SK_DROP;
	}

	{
		u16 offset = preface_offset;
		for (i = 0; i < ARRAY_SIZE(c->rsp); i++) {
			struct frame_header *fh;
			void *data = (void *)(long)skb->data;
			void *data_end = (void *)(long)skb->data_end;

			if (data + offset + sizeof(*fh) > data_end) {
				break;
			}
			fh = data + offset;
			u16 frame_len = frame_length(fh);
			// bpf_printk("frame type %d %u", fh->frame_type,
			// 	   frame_len);

			if (fh->frame_type == SETTINGS_FRAME) {
				if ((fh->flags & FLAGS_ACK) == 0) {
					struct response *r = &c->rsp[nr_rsp++];
					r->response_type = SETTINGS_FRAME;
				}
			} else if (fh->frame_type == DATA_FRAME) {
				struct response *r = &c->rsp[nr_rsp++];
				r->response_type = DATA_FRAME;
				r->common.data.stream_id = fh->stream_id;
				r->common.data.length = frame_length(fh);
			} else if (fh->frame_type == PING_FRAME) {
				if ((fh->flags & FLAGS_ACK) == 0) {
					struct response *r = &c->rsp[nr_rsp++];
					r->response_type = PING_FRAME;
					bpf_skb_load_bytes(skb,
							   offset + sizeof(*fh),
							   (void *)&c->ping, 8);
				}
			}
			offset += (frame_len + sizeof(*fh));
		}
	}

	if (nr_rsp == 0) {
		return SK_DROP;
	}

	u32 len = 0;
	for (i = 0; i < nr_rsp; i++) {
		struct frame_header *h;
		struct response *r = &c->rsp[i];
		switch (r->response_type) {
		case SETTINGS_FRAME: {
			struct settings *s = &r->common.set;

			if (s->identifier == 0) {
				len += FRAME_HEADER_LEN;
			} else {
				len += FRAME_HEADER_LEN + 6;
			}
			break;
		}
		case DATA_FRAME:
			// window update
			len += FRAME_HEADER_LEN + sizeof(u32);
			// ping
			len += FRAME_HEADER_LEN + sizeof(u64);
			// data
			len += FRAME_HEADER_LEN + ARRAY_SIZE(data_payload);

			if (c->header_cached) {
				len += FRAME_HEADER_LEN +
				       ARRAY_SIZE(cached_header1);
				len += FRAME_HEADER_LEN +
				       ARRAY_SIZE(cached_header2);
			} else {
				len += FRAME_HEADER_LEN +
				       ARRAY_SIZE(uncached_header1);
				len += FRAME_HEADER_LEN +
				       ARRAY_SIZE(uncached_header2);
			}
			break;
		case PING_FRAME:
			len += FRAME_HEADER_LEN + sizeof(u64);
			break;
		}
	}

	if (skb->data_end - skb->data != len) {
		s32 delta = len - (skb->data_end - skb->data);
		int err = bpf_skb_adjust_room(skb, delta, 0, 0);
		if (err != 0) {
			bpf_printk("failed to ajust room: %d %d %d", err,
				   skb->data_end - skb->data, delta);
			return SK_DROP;
		}
	}

	u16 offset = 0;
	for (i = 0; i < nr_rsp && i < ARRAY_SIZE(c->rsp); i++) {
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
		struct response *r = &c->rsp[i];

		struct frame_header *h;
		if (data + offset + sizeof(*h) > data_end) {
			return SK_DROP;
		}

		h = data + offset;
		if (r->response_type == SETTINGS_FRAME) {
			struct settings *s = &r->common.set;

			if (s->identifier == 0) {
				update_frame_header(h, 0, SETTINGS_FRAME,
						    FLAGS_ACK, 0);
				offset += sizeof(*h);
			} else {
				update_frame_header(h, 6, SETTINGS_FRAME, 0, 0);
				struct settings *set;
				if (data + offset + sizeof(*h) + sizeof(*set) >
				    data_end) {
					return SK_DROP;
				}
				set = data + offset + sizeof(*h);
				set->identifier = s->identifier;
				set->value = s->value;
				offset += sizeof(*h) + sizeof(*set);
			}
		} else if (r->response_type == PING_FRAME) {
			update_frame_header(h, 8, PING_FRAME, FLAGS_ACK, 0);
			if (data + offset + sizeof(*h) + sizeof(u64) >
			    data_end) {
				return SK_DROP;
			}
			u64 *v = data + offset + sizeof(*h);
			*v = c->ping;
			offset += sizeof(*h) + sizeof(u64);
		} else if (r->response_type == DATA_FRAME &&
			   c->header_cached > 0) {
			update_frame_header(h, 4, WINDOW_UPDATE_FRAME, 0, 0);
			if (data + offset + sizeof(*h) + sizeof(u32) >
			    data_end) {
				return SK_DROP;
			}
			u32 *inc = data + offset + sizeof(*h);
			*inc = htonl(r->common.data.length);
			offset += sizeof(*h) + sizeof(u32);

			// ping
			if (data + offset + sizeof(*h) > data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, 8, PING_FRAME, 0, 0);
			if (data + offset + sizeof(*h) + sizeof(u64) >
			    data_end) {
				return SK_DROP;
			}
			u64 *v = data + offset + sizeof(*h);
			*v = (u64)bpf_get_prandom_u32();
			offset += sizeof(*h) + sizeof(u64);

			//headers1
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(cached_header1) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(cached_header1),
					    HEADERS_FRAME, 0x04,
					    r->common.data.stream_id);

			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)cached_header1,
					 ARRAY_SIZE(cached_header1));
			offset += sizeof(*h) + ARRAY_SIZE(cached_header1);

			// data
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(data_payload) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(data_payload),
					    DATA_FRAME, 0,
					    r->common.data.stream_id);
			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)data_payload,
					 ARRAY_SIZE(data_payload));
			offset += sizeof(*h) + ARRAY_SIZE(data_payload);

			//headers2
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(cached_header2) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(cached_header2),
					    HEADERS_FRAME, 0x05,
					    r->common.data.stream_id);
			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)cached_header2,
					 ARRAY_SIZE(cached_header2));
			offset += sizeof(*h) + ARRAY_SIZE(cached_header2);
		} else {
			update_frame_header(h, 4, WINDOW_UPDATE_FRAME, 0, 0);
			if (data + offset + sizeof(*h) + sizeof(u32) >
			    data_end) {
				return SK_DROP;
			}
			u32 *inc = data + offset + sizeof(*h);
			*inc = htonl(r->common.data.length);
			offset += sizeof(*h) + sizeof(u32);

			// ping
			if (data + offset + sizeof(*h) > data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, 8, PING_FRAME, 0, 0);
			if (data + offset + sizeof(*h) + sizeof(u64) >
			    data_end) {
				return SK_DROP;
			}
			u64 *v = data + offset + sizeof(*h);
			*v = (u64)bpf_get_prandom_u32();
			offset += sizeof(*h) + sizeof(u64);

			//headers1
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(uncached_header1) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(uncached_header1),
					    HEADERS_FRAME, 0x04,
					    r->common.data.stream_id);

			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)uncached_header1,
					 ARRAY_SIZE(uncached_header1));
			offset += sizeof(*h) + ARRAY_SIZE(uncached_header1);

			// data
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(data_payload) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(data_payload),
					    DATA_FRAME, 0,
					    r->common.data.stream_id);
			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)data_payload,
					 ARRAY_SIZE(data_payload));
			offset += sizeof(*h) + ARRAY_SIZE(data_payload);

			//headers2
			if (data + offset + sizeof(*h) +
				    ARRAY_SIZE(uncached_header2) >
			    data_end) {
				return SK_DROP;
			}
			h = data + offset;
			update_frame_header(h, ARRAY_SIZE(uncached_header2),
					    HEADERS_FRAME, 0x05,
					    r->common.data.stream_id);
			__builtin_memcpy(data + offset + sizeof(*h),
					 (void *)uncached_header2,
					 ARRAY_SIZE(uncached_header2));
			offset += sizeof(*h) + ARRAY_SIZE(uncached_header2);
		}
		if (r->response_type == DATA_FRAME && c->header_cached == 0) {
			c->header_cached = 1;
			bpf_map_update_elem(&clientmap, &key, c, BPF_EXIST);
		}
	}

	int err = bpf_sk_redirect_hash(skb, &sockhash, &key, 0);
	// bpf_printk("sent %d bytes, %d %d", len, skb->data_end - skb->data, err);
	return err;
}

SEC("sockops")
int _sock_ops(struct bpf_sock_ops *ops)
{
	int op;
	op = (int)ops->op;

	if (ops->local_port != GRPC_PORT) {
		return 0;
	}

	u64 key = ((u64)ops->remote_ip4 << 32) | ops->remote_port;
	// TCP_CLOSE
	if (op == BPF_SOCK_OPS_STATE_CB && ops->args[1] == 7) {
		// bpf_printk("state change %u %u", ops->args[1], ops->args[2]);
		bpf_map_delete_elem(&clientmap, &key);
		return 0;
	}

	if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
	    op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		struct client nc;
		__builtin_memset(&nc, 0, sizeof(nc));
		bpf_map_update_elem(&clientmap, &key, &nc, 0);

		bpf_sock_ops_cb_flags_set(ops,
					  ops->bpf_sock_ops_cb_flags |
						  BPF_SOCK_OPS_STATE_CB_FLAG);
		bpf_sock_hash_update(ops, &sockhash, &key, 0);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
