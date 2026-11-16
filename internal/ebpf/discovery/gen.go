package discovery

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event -type edge_key -type edge_val -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" discovery ../../../bpf/discovery.c
