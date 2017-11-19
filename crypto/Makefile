ifneq ($(KERNELRELEASE),)
	obj-m := encrypt.o aes_test.o
else
	KERNELDIR := $(EC535)/gumstix/linux-2.6.21gum/
	KERNELDIR_GUM := $(EC535)/gumstix/oe/linux-2.6.21/
	PWD := $(shell pwd)
	ARCH := arm
	CROSS := arm-linux-

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) modules

gumstix:
	$(MAKE) -C $(KERNELDIR_GUM) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) modules

encrypt2sd: encrypt2sd.o
	arm-linux-gcc -o encrypt2sd encrypt2sd.o

encrypt2sd.o: encrypt2sd.c
	arm-linux-gcc -c encrypt2sd.c -o encrypt2sd.o



clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) clean
	rm encrypt2sd

endif
