/* eBPF example program:
 * - creates arraymap in kernel with key 4 bytes and value 8 bytes
 *
 * - loads eBPF program:
 *   r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)];
 *   *(u32*)(fp - 4) = r0;
 *   // assuming packet is IPv4, lookup ip->proto in a map
 *   value = bpf_map_lookup_elem(map_fd, fp - 4);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to loopback interface "lo" raw socket
 *
 * - every second user space reads map[tcp], map[udp], map[icmp] to see
 *   how many packets of given protocol were seen on "lo"
 */
#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/ioctl.h>
#include "bpf_insn.h"

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int perf_event_open(struct perf_event_attr *attr,
		    pid_t pid, int cpu, int group_fd,
		    unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

#define BPF_LOG_SIZE (1024*1024)
char bpf_log_buf[BPF_LOG_SIZE];

static int test_sock(void)
{
    int sock = -1, map_fd, prog_fd, i, key, ret, efd;
    long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;
    struct perf_event_attr pattr = {0};
    union bpf_attr attr = {
	.map_type    = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(key),
	.value_size  = sizeof(value),
	.max_entries = 256
    };
	
    map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	
    //map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(key), sizeof(value),
    //			256, NULL);
    if (map_fd < 0) {
	printf("failed to create map '%s'\n", strerror(errno));
	goto cleanup;
    }

    struct bpf_insn prog[] = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	//BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol) /* R0 = ip->proto */),
	BPF_MOV64_IMM(BPF_REG_0, IPPROTO_ICMP), /* r0 = 0 */
	BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
	BPF_LD_MAP_FD(BPF_REG_1, map_fd),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
	BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_0, BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
	BPF_EXIT_INSN(),
    };
    size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    for(i = 0; i < insns_cnt; i++) {
	printf("%d %02x\n", i, prog[i].code);
    }
    bpf_log_buf[0] = '\0';
    /*
      opts.kern_version = KERNEL_VERSION(5, 15, 39);	
      LIBBPF_OPTS(bpf_prog_load_opts, opts,
      .log_buf = bpf_log_buf,
      .log_size = BPF_LOG_SIZE,
      );
      prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
      prog, insns_cnt, &opts);
    */
    //printf("log_size = %d, %d\n", BPF_LOG_SIZE, opts.kern_version);
	
    {
	union bpf_attr bpfa;
	memset(&bpfa, 0, sizeof(bpfa));
	//bpfa.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	//bpfa.prog_type = BPF_PROG_TYPE_KPROBE;
	bpfa.prog_type = BPF_PROG_TYPE_TRACEPOINT;
	
	bpfa.insn_cnt   = insns_cnt;
	bpfa.insns = (__u64)prog;
	bpfa.license = (__u64)"GPL";
	bpfa.log_level = 1;
	bpfa.log_size = BPF_LOG_SIZE;
	bpfa.log_buf = (__u64)bpf_log_buf;
	bpfa.kern_version = LINUX_VERSION_CODE;
	prog_fd = bpf(BPF_PROG_LOAD, &bpfa, sizeof(bpfa));
    }
    printf("%s\n", bpf_log_buf);
    if (prog_fd < 0) {
	printf("failed to load prog '%s'\n", strerror(errno));
	goto cleanup;
    }

    /*
    sock = open_raw_sock("lo");

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		   sizeof(prog_fd)) < 0) {
	printf("setsockopt %s\n", strerror(errno));
	goto cleanup;
    }
    */

    pattr.type = PERF_TYPE_TRACEPOINT;
    pattr.size = sizeof(pattr);
    pattr.config = 738; // sys_enter_unlinkat
    pattr.sample_period = 1;
    pattr.wakeup_events = 1;
    pattr.sample_type = PERF_SAMPLE_RAW;

    efd = perf_event_open(&pattr, 0, -1, -1, 0);
    //efd = perf_event_open(&pattr, -1, 0, -1, 0);
    if(efd < 0) {
	printf("error in efd opening, %s\n", strerror(errno));
	exit(1);
    }        
    ret = ioctl(efd, PERF_EVENT_IOC_RESET, prog_fd);
    if(ret < 0) {
        printf("PERF_EVENT_IOC_RESET error: %s\n", strerror(errno));
        exit(-1);	
    }
    ret = ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (ret < 0) {
        printf("PERF_EVENT_IOC_SET_BPF error: %s\n", strerror(errno));
        exit(-1);
    }    
    ret = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
    if (ret < 0) {
        printf("PERF_EVENT_IOC_ENABLE error: %s\n", strerror(errno));
        exit(-1);
    }
    for (i = 0; i < 10; i++) {
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	key = IPPROTO_TCP;
	attr.key = (__u64)&key;
	attr.value = (__u64)&tcp_cnt;
	bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	
	attr.map_fd = map_fd;
	key = IPPROTO_UDP;
	attr.key = (__u64)&key;
	attr.value =(__u64)&udp_cnt;
	bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));

	attr.map_fd = map_fd;
	key = IPPROTO_ICMP;
	attr.key = (__u64)&key;
	attr.value = (__u64)&icmp_cnt;
	if(bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) != 0) {
	    printf("maplookup failed: %s\n", strerror(errno));
	}
	//assert(icmp_cnt == 0);	
	//assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);
	    
	printf("TCP %lld UDP %lld ICMP %lld packets\n",
	       tcp_cnt, udp_cnt, icmp_cnt);
	sleep(1);
    }

cleanup:
    /* maps, programs, raw sockets will auto cleanup on process exit */
    return 0;
}

int main(void)
{
    FILE *f;

    f = popen("ping -4 -c5 localhost", "r");
    (void)f;

    return test_sock();
}
