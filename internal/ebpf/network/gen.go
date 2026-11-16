package network

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type sample -type dest_key -type connect_hist -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" netquality ../../../bpf/netquality.c
//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event -cflags "-O2 -g -Wall -Werror -I../../../bpf/include" dns ../../../bpf/dns.c
