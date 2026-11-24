# SPDX-License-Identifier: GPL-2.0 OR MIT
# Copyright © 2026 Lei Zhou
# Out-of-tree build against the running kernel's headers, with the
# compiler that built that kernel, by the name the kernel records (gcc-12
# is a link to it; Kbuild warns on the name).
KDIR ?= /lib/modules/$(shell uname -r)/build
CC := x86_64-linux-gnu-gcc-12

# The debug build: the same source with ASX_FAULT (fault injection), in a
# copy of this directory under the workspace's target/, never beside the
# released module.
FAULT_DIR ?= $(abspath $(CURDIR)/../../../target/asx-fault)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) modules

fault:
	mkdir -p $(FAULT_DIR)
	cp anchorstamp_exec.c Kbuild $(FAULT_DIR)/
	$(MAKE) -C $(KDIR) M=$(FAULT_DIR) CC=$(CC) KCFLAGS=-DASX_FAULT modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) clean

.PHONY: all clean fault
