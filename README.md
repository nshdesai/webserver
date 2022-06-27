# Web Server 

A simple, multi-threaded, caching webserver written in C.
The server threading and caching code is in [`server_thread.c`](server_thread.c). The server itself is implemented in [`server.c`](server.c).
If you want to see how the requests are processed, check out [`request.c`](request.c).
In this project, workloads are simulated at two levels of complexity. To see how see [`client_simple.c`](client_simple.c) and [`client.c`](client.c).

This code is **not intended for real-world use**. Please don't use this. 

That said, if you want to play around with it, simply clone the repo and run `make` to build all targets.
This will generate all the executables for benchmarking the server.

Disclaimer: This repo is a cleaned up archive of an assignment written (in|for) school. Please don't plagarize.
