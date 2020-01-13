#
# Copyright 2020 VMware, Inc.
#
# Licensed under the GNU Lesser General Public License version 2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the LICENSE file of this distribution.
#


all:
	(cd user; make all)
	(cd kernel; make all)
 
clean:
	(cd user; make clean)
	(cd kernel; make clean)
