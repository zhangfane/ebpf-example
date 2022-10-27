CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := x86
BPFTOOL ?= /usr/local/sbin/bpftool

LIBBPF_INCLUDES = -I /root/bpftool/src/libbpf/include
LIBBPF_LIBS = -L /root/bpftool/src/libbpf -lbpf

INCLUDES=$(LIBBPF_INCLUDES)
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
BUILD-ARGS= -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option
all: build

build: pid

pid.bpf.o: pid.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)  -c pid.bpf.c

pid.skel.h: pid.bpf.o
	$(BPFTOOL) gen skeleton pid.bpf.o > pid.skel.h

pid: pid.skel.h pid.c
	$(CLANG)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o pid pid.c $(LIBBPF_LIBS) -lelf -lz