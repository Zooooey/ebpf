#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"
struct cost_ctx {
	uint64_t pre_do_swap_page; 
	uint64_t pre_swap_readpage;
	uint64_t post_swap_readpage;
};

int main(int argc, char **argv)
{
		if(load_bpf_file("ccy_swap_kern.o") != 0)
		{
				printf("The kernel didn't load BPF program\n");
				printf("errno: %d, error msg: %s\n", errno, strerror(errno));
				return -1;
		}
		int fd = map_fd[0];
		pid_t pid = getpid();
		printf("user space pid :%u\n",pid);
		struct cost_ctx value = {
			.pre_do_swap_page=0,
			.pre_swap_readpage=0,
			.post_swap_readpage=0,
		};
		int ret = bpf_map_update_elem(fd, &pid, &value, 0);
		if(ret == 0)    {
				printf("Insert value into bpf map success!\n");
		}else {
				printf("update context of pid:%llu into ebpf map failed!\n", pid);
				printf("errno: %d, error msg: %s\n", errno, strerror(errno));
				return -1;
		}
		printf("entering dead loop to waiting....\n");
		while(true);
		return 0;
}

