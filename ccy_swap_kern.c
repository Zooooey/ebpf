#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>
#include "bpf_helpers.h"


#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") ctx_map = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u32),
		.value_size = sizeof(u32),
		.max_entries = 1024,
};

SEC("kprobe/do_swap_page")
int pre_do_page_fault(struct pt_regs *regs){
		u32 kpid = bpf_get_current_pid_tgid() >>32;
		char fmt[] = "pid: %u call do_swap_page!\n";
		bpf_trace_printk(fmt, sizeof(fmt) , kpid);
		return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

