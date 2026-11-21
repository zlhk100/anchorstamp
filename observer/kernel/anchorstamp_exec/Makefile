# SPDX-License-Identifier: GPL-2.0 OR MIT
# Out-of-tree build against the running kernel's headers, with the
# compiler that built that kernel, by the name the kernel records (gcc-12
# is a link to it; Kbuild warns on the name).
KDIR ?= /lib/modules/$(shell uname -r)/build
CC := x86_64-linux-gnu-gcc-12

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) clean

.PHONY: all clean
