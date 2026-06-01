nexus-objs := nexus_core.o port.o sem.o
nexus_node_monitor-objs := node_monitor.o vref.o query.o attribute.o index.o volume.o
obj-m := nexus.o area.o nexus_node_monitor.o

KERNEL_SRC  ?= /lib/modules/$(shell uname -r)/build

PWD   := $(shell pwd)

WORKING_DIR ?= $$PWD

export EXTRA_CFLAGS := -std=gnu11

default: $(PWD)/Makefile
	$(MAKE) -C $(KERNEL_SRC) M=$(WORKING_DIR) MO=$(WORKING_DIR)/build/ src=$(PWD) modules

install:
	cp build/nexus.ko $(DESTDIR)/
	cp build/area.ko $(DESTDIR)/
	cp build/nexus_node_monitor.ko $(DESTDIR)/

clean:
	rm -rf deps.h *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions *.mod *.o .*.o .*.d
