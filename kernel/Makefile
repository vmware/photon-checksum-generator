#
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: GPL v2.0
#
# Licensed under the GNU Lesser General Public License version 2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the LICENSE file of this distribution.
#

obj-m += hmac_generator.o
hmac_generator-objs :=  drv_hmac_gen.o hmac_gen.o

EXTRA_CFLAGS=-I..//include  
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
