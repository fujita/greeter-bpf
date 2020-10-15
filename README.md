greeter-bpf is an experiment on implementing server software in eBPF. It works as gRPC GreeterServer only for the benchmark. It's tested with libbpf.
(b6dd2f2b).

# Performance

## Hardware and Software

Same as [the Rust greeter](https://github.com/fujita/greeter).

## Benchmark

```
ghz --insecure --proto /var/opt/helloworld.proto --call helloworld.Greeter.SayHello -d '{"name":"Joe"}' --connections=3000 -c 3000 -n 6000000 -t 0 172.31.21.68:50051

```

- One client machine runs 3,000 gRPC clients (i.e. 3,000 HTTP/2 clients).
- One client issues 6,000,000 requests in total.
- Tested with one, two, and four client matchies.

## Results

Throughput (requests per second)

|        |3000  |6000  |12000 |24000 |
---------|------|------|------|-------
|     bpf|246025|485305|906581|453259|
| grpc-go|227356|331013|301632|287175|
|   async|231914|450984|441548|415015|

![Throughput (requests per second)](https://miro.medium.com/max/700/1*k1WbgZK5DGdYgxapebG_Gg.png)
