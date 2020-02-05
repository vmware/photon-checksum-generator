/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License version 2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the LICENSE file of this distribution.
 */

#include <linux/ioctl.h>
#define DEVICE_NAME "hmac_gen"
#define MAJOR_NUM 91
#define KEY_SIZE 256
#define HMAC_MAX_FILEPATH_LEN 1024
#define HMAC_MAX_OUT_LEN 64

// Crypto Algo Types
enum {
	HMAC_SHA256 = 1,
	HMAC_SHA512
};

#define IOCTL_SET_KEY _IOW(MAJOR_NUM, 1, char *)
#define IOCTL_SET_ALGO _IOW(MAJOR_NUM, 2, int *)
#define IOCTL_SET_FILEPATH _IOW(MAJOR_NUM, 3, char *)
