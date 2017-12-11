ifneq ($(KERNELRELEASE),)
	obj-m := file_crypto.o aes_test.o#encrypt.o decrypt.o aes_test.o
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

fct: fct.o
	arm-linux-gcc -o fct fct.o

fct.o: fct.c
	arm-linux-gcc -c fct.c -o fct.o


clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) clean

endif
