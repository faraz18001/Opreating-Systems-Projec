CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
PYTHON ?= python3

CFLAGS := -O2 -Wall -Wextra
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Iebpf

.PHONY: all red_team ebpf clean

all: red_team ebpf

red_team: red_team/build/loader

red_team/build/payload: red_team/payload.c
	@mkdir -p red_team/build
	$(CC) $(CFLAGS) -o $@ $<

red_team/build/payload_bytes.h: red_team/build/payload red_team/pack_payload.py
	$(PYTHON) red_team/pack_payload.py red_team/build/payload $@

red_team/build/loader: red_team/loader.c red_team/build/payload_bytes.h
	$(CC) $(CFLAGS) -o $@ red_team/loader.c

ebpf: ebpf/build/probes.bpf.o ebpf/build/sensor

ebpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ebpf/build/probes.bpf.o: ebpf/probes.bpf.c ebpf/events.h ebpf/vmlinux.h
	@mkdir -p ebpf/build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpf/build/sensor: ebpf/sensor.c ebpf/events.h
	@mkdir -p ebpf/build
	$(CC) $(CFLAGS) -Iebpf -o $@ $< -lbpf -lelf -lz

clean:
	rm -rf red_team/build/* ebpf/build/*
