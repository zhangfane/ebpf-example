
#include "vmlinux.h"
#include "bpf/bpf_tracing.h"
#include "pid.h"
#include <bpf/bpf_helpers.h>

#define READ_KERN_V(ptr)                                   \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })


/*定义BPF_HASH中的值*/


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
//    struct ipv4_key_t* key;
    __type(key,struct ipv4_key_t*);
    __type(value, u64*);
} ipv4_send_bytes SEC(".maps");


/*探测内核中的 tcp_sendmsg 函数 */
SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    u64 *size = (u64 *) PT_REGS_PARM3(ctx);

    /*获取当前进程的pid*/
    u64 pid = bpf_get_current_pid_tgid();

    u16 family = READ_KERN_V(sk->__sk_common.skc_family);
    /*判断是否是IPv4*/
    if (family == 2) {

        struct ipv4_key_t ipv4_key = {.pid = pid};
        u64 *val = NULL;
        val = bpf_map_lookup_elem(&ipv4_send_bytes, &ipv4_key);
        if (val != NULL) {
            val = *val + size;
            bpf_printk("djklsjadklajlkd");
            bpf_printk("current size: %d",size);
            bpf_printk("pid:%d,send total:%d", pid, val);

            bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &val, BPF_ANY);
        } else {
            val = (u64 *) size;
            bpf_printk("qqqqqq");
            bpf_printk("%d", val);
            u64 a = 1233321;
            bpf_printk("%d", sizeof(a));

            bpf_printk("%d", sizeof(val));
            bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &val, BPF_ANY);
        }


    }
    return 0;
}
//
//struct {
//    __uint(type, BPF_MAP_TYPE_HASH);
//    __uint(max_entries, 128);
//    __type(key,struct ipv4_key_t*);
//    __type(value, u64);
//}ipv4_recv_bytes SEC(".map");
//
////BPF_MAP_TYPE_HASH(ipv4_recv_bytes, struct ipv4_key_t);
///*探测内核中的 tcp_cleanup_rbuf 函数 */
//SEC("kprobe/tcp_cleanup_rbuf")
//int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied,u32 spec_pid)
//{
//    /*获取当前进程的pid*/
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
//    /*此部分在python里处理，用于替换特定功能的c语句*/
//    if (pid != spec_pid) { return 0; }
//    /*获取网络协议的套接字类型*/
//    u16 family = sk->__sk_common.skc_family;
//    /*检错*/
//    if (copied <= 0)
//        return 0;
//    /*判断是否是IPv4*/
//    if (family == 2) {
//        /*将当前进程的pid放入ipv4_key结构体中
//          作为ipv4_send_bytes哈希表的关键字*/
//        struct ipv4_key_t ipv4_key = {.pid = pid};
//        /*将copied的值作为哈希表的值进行累加*/
//        u64 *val=NULL;
//        val=bpf_map_lookup_elem(&ipv4_recv_bytes,&ipv4_key);
//        if (val!=NULL){
//            *val+=copied;
//        }
//    }
//    return 0;
//}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
