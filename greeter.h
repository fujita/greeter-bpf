#define MAX_CLIENT 65536
#define GRPC_PORT 50051

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct settings {
	__u16 identifier;
	__u32 value;
} __attribute__((packed));

struct response {
	__u8 response_type;
	union {
		struct settings set;
		struct {
			__u32 stream_id;
			__u32 length;
		} data;
	} common;
};

struct client {
	__u64 ping;
	__u64 key;
	__u32 fd;
	__u8 established;
	__u8 header_cached;
	struct response rsp[16];
};
