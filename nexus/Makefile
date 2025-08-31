obj-m := nexus.o 

KERNEL_SRC  ?= /lib/modules/$(shell uname -r)/build

PWD   := $(shell pwd)

WORKING_DIR ?= $$PWD/build

export EXTRA_CFLAGS := -std=gnu11

default: $(PWD)/Makefile
	$(MAKE) -C $(KERNEL_SRC) M=$(WORKING_DIR) src=$(PWD) modules

install:
	cp build/nexus.ko $(DESTDIR)/

clean:
	rm -rf deps.h *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions
