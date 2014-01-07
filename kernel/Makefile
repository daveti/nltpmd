# nltpmd kernel module for testing
# Jan 7, 2014
# root@davejingtian.org
# http://davejingtian.org
obj-m += nltpmd_kernel_mod.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
