#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>
#include "bpf_helpers.h"


#define SEC(NAME) __attribute__((section(NAME), used))

struct cost_ctx {
	u64 do_swap_page; // start time of 'do_swap_page' being called.
	u64 frontswap_load;// end time after 'frontswap_load' been called.
	u64 swap_readpage;// end time after 'swap_readpage' been called.
};

struct bpf_map_def SEC("maps") ctx_map = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u32),
		.value_size = sizeof(struct cost_ctx),
		.max_entries = 1024,
};

SEC("kprobe/do_swap_page")
static u64 ccy_time_do_swap_page = 0;
int pre_swap_readpage(struct pt_regs *regs){
		// u32 kpid = bpf_get_current_pid_tgid() >>32;
		// u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		ccy_time_do_swap_page = bpf_ktime_get_boot_ns();
		// char fmt[] = "pid: %u tpid:%u call do_swap_page!\n";
		// bpf_trace_printk(fmt, sizeof(fmt) , kpid, tpid);
		return 0;
}

SEC("kprobe/swap_readpage")
static u64 ccy_time_swap_readpage = 0;
int post_swap_readpage(struct pt_regs *regs){
		// u32 kpid = bpf_get_current_pid_tgid() >>32;
		// u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		ccy_time_swap_readpage = bpf_ktime_get_boot_ns();
		// char fmt[] = "pid: %u tpid:%u after call swap_readpage!\n";
		// bpf_trace_printk(fmt, sizeof(fmt) , kpid, tpid);
		return 0;
}

SEC("kretprobe/swap_readpage")
int post_swap_readpage(struct pt_regs *regs){
	    u64 now = bpf_ktime_get_boot_ns();
		u32 kpid = bpf_get_current_pid_tgid() >>32;
		u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		u64 kernel_stack = ccy_time_swap_readpage - ccy_time_do_swap_page;
		u64 read_disk = now - ccy_time_swap_readpage;
		char fmt[] = "pid: %u tpid:%u after call swap_readpage! kernel_stack:%lu us read_ssd:%lu us\n";
		bpf_trace_printk(fmt, sizeof(fmt) , kpid, tpid, kernel_stack, read_disk);
		return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

