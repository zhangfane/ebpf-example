CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPFTOOL ?= /usr/local/sbin/bpftool

LIBBPF_TOP = /root/bpftool/src/libbpf/include

LIBBPF_UAPI_INCLUDES = -I $(LIBBPF_TOP)/include/uapi
LIBBPF_INCLUDES = -I /root/bpftool/src/libbpf/include
LIBBPF_LIBS = -L /root/bpftool/src/libbpf/ -lbpf
LINUX_SOURCE = /usr/src/linux-source-5.19.0
INCLUDES=$(LIBBPF_INCLUDES)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')


all: build

build: helloworld

helloworld.bpf.o: helloworld.bpf.c
	$(CLANG)  -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c helloworld.bpf.c

helloworld.skel.h: helloworld.bpf.o
	$(BPFTOOL) gen skeleton helloworld.bpf.o > helloworld.skel.h

helloworld: helloworld.skel.h helloworld.c
	$(CLANG)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o helloworld helloworld.c $(LIBBPF_LIBS) -lbpf -lelf -lz