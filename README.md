## Custom loadbalancing for SO_REUSEPORT with eBPF

Code for [eBPF summit 2023](https://ebpf.io/summit-2023/) talk - `Hot standby load balancing with SO_REUSEPORT and eBPF`

SO_REUSEPORT is a powerful feature of the Linux kernel that allows users to have more than one process listen on a given port and allow for load balancing between them. The default load-balancing strategy is round-robin, but with the help of eBPF, we can take this feature one step further and implement other load-balancing strategies. In this lightning talk, you’ll learn to implement weighted and hot standby load balancing with nothing but eBPF and SO_REUSEPORT.

```
➜  reuseport_ebpf git:(main) go run server.go primary
2023-09-13T13:05:25.895Z	INFO	Starting server in primary mode
2023-09-13T13:05:25.900Z	INFO	Started listening in 127.0.0.1:8080 successfully !
2023-09-13T13:05:25.900Z	INFO	Updating with k=0 v=7
2023-09-13T13:05:25.900Z	INFO	Map update for tcp_balancing_targets succeeded
```

```
➜  reuseport_ebpf git:(main) go run server.go standby
2023-09-13T13:07:14.249Z	INFO	Starting server in standby mode
2023-09-13T13:07:14.253Z	INFO	Started listening in 127.0.0.1:8080 successfully !
2023-09-13T13:07:14.253Z	INFO	Updating with k=1 v=7
2023-09-13T13:07:14.253Z	INFO	Map update for tcp_balancing_targets succeeded
```

```
➜  reuseport_ebpf git:(main) curl localhost:8080/hello
Hello eBPF Summit 2023 - primary!
```