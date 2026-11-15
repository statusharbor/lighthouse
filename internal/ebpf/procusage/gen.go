package procusage

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type proc_key -type cpu_val -type io_val -type latency -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" usage ../../../bpf/usage.c
