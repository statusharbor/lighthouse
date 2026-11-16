package hello

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" hello ../../../bpf/hello.c
