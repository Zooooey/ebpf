#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct cost_ctx
{
	u64 time_swap;//the time 'do_swap_page' be called.
	u64 time_pre_read;//the time 'swap_readpage' be called.
	u64 time_post_read;//the time 'swap_readpage' completed.
};

struct bpf_map_def SEC("maps") ctx_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct cost_ctx),
	.max_entries = 1024,
};

SEC("kprobe/do_swap_page")
int pre_do_swap_page(struct pt_regs *regs)
{
	u32 kpid = bpf_get_current_pid_tgid() >> 32;
	u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	u64 ccy_time_do_swap_page = bpf_ktime_get_ns();
	struct cost_ctx *value = (struct cost_ctx *)bpf_map_lookup_elem(&ctx_map, &tpid);
	if (!value)
	{
		bpf_trace_printk("tpid:%lu not in bpf map!\n", tpid);
	}
	else
	{
		value->pre_do_swap_page = ccy_time_do_swap_page;
		bpf_map_update_elem(&ctx_map, &tpid, &value, 0);
	}
	// char fmt[] = "pid: %u tpid:%u call do_swap_page!\n";
	// bpf_trace_printk(fmt, sizeof(fmt) , kpid, tpid);
	return 0;
}

SEC("kprobe/swap_readpage")
int pre_swap_readpage(struct pt_regs *regs)
{
	u32 kpid = bpf_get_current_pid_tgid() >> 32;
	u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	u64 ccy_time_swap_readpage = bpf_ktime_get_ns();
	struct cost_ctx *value = (struct cost_ctx *)bpf_map_lookup_elem(&ctx_map, &tpid);
	if (!value)
	{
		bpf_trace_printk("tpid:%lu not in bpf map!\n", tpid);
	}
	else
	{
		value->pre_swap_readpage = ccy_time_swap_readpage;
		bpf_map_update_elem(&ctx_map, &tpid, &value, 0);
	}
	// char fmt[] = "pid: %u tpid:%u after call swap_readpage!\n";
	// bpf_trace_printk(fmt, sizeof(fmt) , kpid, tpid);
	return 0;
}

SEC("kretprobe/swap_readpage")
int post_swap_readpage(struct pt_regs *regs)
{
	u64 now = bpf_ktime_get_ns();
	u32 kpid = bpf_get_current_pid_tgid() >> 32;
	u32 tpid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	struct cost_ctx *value = (struct cost_ctx *)bpf_map_lookup_elem(&ctx_map, &tpid);
	if (!value)
	{
		bpf_trace_printk("tpid:%lu not in bpf map\n", tpid);
	}
	else
	{
		
		u64 kernel_stack = value->pre_swap_readpage - value->pre_do_swap_page;
		u64 read_disk = now - value->pre_swap_readpage;
		char fmt[] = "pid: %u tpid:%u after call swap_readpage! \n";
		bpf_trace_printk(fmt, sizeof(fmt), kpid, tpid);
		char cost[] = "kernel_stack:%lu us read_ssd:%lu us\n";
		bpf_trace_printk(cost, sizeof(cost), kernel_stack / 1000, read_disk / 1000);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
