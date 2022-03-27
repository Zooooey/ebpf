#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"


int main(int argc, char **argv)
{
		if(load_bpf_file("ccy_swap_kern.o") != 0)
		{
				printf("The kernel didn't load BPF program\n");
				printf("errno: %d, error msg: %s\n", errno, strerror(errno));
				return -1;
		}
		int fd = map_fd[0];
		int value = 0;
		pid_t pid = getpid();
		printf("user space pid :%u\n",pid);
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

