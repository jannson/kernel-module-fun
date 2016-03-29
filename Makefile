export CROSS_COMPILE=arm-brcm-linux-uclibcgnueabi-
export ARCH=arm

obj-m += hello.o
obj-m += hello-packet.o
obj-m += rootkit.o
#obj-m += rickroll.o
obj-m += excited_virus.o
obj-m += redirect.o
obj-m += tproxy.o

NET=/projects/R8500-V1.0.2.54_1.0.56_src/components/opensource/linux/linux-2.6.36

merlin:
	make -C /projects/asuswrt-merlin-68-378-56/release/src-rt-6.x.4708/linux/linux-2.6.36 ARCH=arm M=$(PWD) modules

netgear:
	make -C $(NET) ARCH=arm M=$(PWD) modules

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
