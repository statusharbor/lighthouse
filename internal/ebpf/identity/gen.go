package identity

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" identity ../../../bpf/identity.c
