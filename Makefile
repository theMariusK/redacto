.PHONY: all clean generate build

all: vmlinux.h generate build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

generate: vmlinux.h
	go generate ./...

build: generate
	go build -o redacto .

clean:
	rm -f vmlinux.h bpf_*.go bpf_*.o redacto
