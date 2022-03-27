#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"
struct cost_ctx {
	long do_swap_page; // start time of 'do_swap_page' being called.
	long frontswap_load;// end time after 'frontswap_load' been called.
	long swap_readpage;// end time after 'swap_readpage' been called.
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
			.do_swap_page=0,
			.frontswap_load=0,
			.swap_readpage=0,
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

