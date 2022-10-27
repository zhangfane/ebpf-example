//
// Created by 张帆 on 2022/10/20.
//
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "pid.skel.h"

typedef __u64 u64;
struct ipv4_key_t {
    u64 pid;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct pid_bpf *skel;
    int err;

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
    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);
        struct ipv4_key_t key = {.pid = 30480};
        u64* v;
        err = bpf_map__lookup_elem(skel->maps.ipv4_send_bytes, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
//        if (err != 0) {
//            fprintf(stderr, "Lookup key from map error: %d\n", err);
//            goto cleanup;
//        } else {
//            printf("execve_counter is %llu\n", v);
//        }

        sleep(5);
    }

    cleanup:
    pid_bpf__destroy(skel);
    return -err;
}