//
// Created by 张帆 on 2022/10/20.
//
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "pid.skel.h"
#include "arpa/inet.h"
typedef __u64 u64;
typedef __u32 u32;

struct ipv4_key_t {
    int pid;
};

struct ipv4_value_t {
    u64 value;
    u64 saddr;
    u64 daddr;
    u32 lport;
    u32 dport;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct pid_bpf *skel;
    int err,err2;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = pid_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = pid_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = pid_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");
//    for (;;) {
//        /* trigger our BPF program */
//        fprintf(stderr, ".");
//        sleep(1);
//    }
//
//    for (;;) {
//
//        // read counter value from map
//        //
//        //LIBBPF_API int bpf_map__lookup_elem(const struct bpf_map *map,
//        //        const void *key, size_t key_sz,
//        //        void *value, size_t value_sz, __u64 flags);
//        //        /usr/local/bpf/include/bpf/libbpf.h
////        uint64_t key=110;
////        void *val;
////        err = bpf_map__lookup_elem(skel->maps.ipv4_send_bytes, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
////        if (err != 0) {
////            fprintf(stderr, "Lookup key from map error: %d\n", err);
////            goto cleanup;
////        } else {
//////            printf("execve_counter is \n", val);
////        }
//
//        sleep(5);
//    }
//
    printf("%-10s %-12s %-10s %-10s %-10s %-10s %-10s\n", "进程ID","进程名称","RX_KB(已接收字节数)","TX_KB(已发送字节数)","RXSUM_KB","TXSUM_KB","TOTAL_KB");
    for (;;) {
        /* trigger our BPF program */
//        fprintf(stderr, ".");
        sleep(5);
        struct ipv4_key_t key = {.pid=56549};
        u64 received_v ;
        struct ipv4_value_t send_v;
        err = bpf_map__lookup_elem(skel->maps.ipv4_recv_bytes, &key, sizeof(key), &received_v, sizeof(received_v), BPF_ANY);
        err2 = bpf_map__lookup_elem(skel->maps.ipv4_send_bytes, &key, sizeof(key), &send_v, sizeof(send_v), BPF_ANY);

        if (err != 0 || err2!=0) {
            fprintf(stderr, "Lookup key from map error: %d,err2:%d\n", err,err2);
//            goto cleanup;
        } else {
            printf("%-10d %-12s %-10llu %-10llu %-10llu %-10llu %-10llu\n", key.pid,"进程名称",received_v,send_v.value,received_v,send_v.value,received_v+send_v.value);
        }
        sleep(5);
    }
    cleanup:
    pid_bpf__destroy(skel);
    return -err;
}