obj-m := nexus.o 

KDIR  := /lib/modules/$(shell uname -r)/build

PWD   := $(shell pwd)

export EXTRA_CFLAGS := -std=gnu99


default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
