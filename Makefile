obj-m := nexus.o 

KDIR  ?= /lib/modules/$(shell uname -r)/build

PWD   := $(shell pwd)

BUILD_DIR ?= $(PWD)/build

export EXTRA_CFLAGS := -std=gnu11

default: $(PWD)/Makefile
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) modules
