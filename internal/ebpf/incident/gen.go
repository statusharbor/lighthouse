package incident

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event -type conn_key -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" incident ../../../bpf/incident.c
