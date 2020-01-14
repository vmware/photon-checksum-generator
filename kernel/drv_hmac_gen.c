/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License version 2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the LICENSE file of this distribution.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <crypto/hash.h>
#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <asm/byteorder.h>

#include "../include/hmac_gen_ioctl.h"
#include "../include/hmac_gen.h"

static hmacgen_out_data *hmacgen_data;
static int hmacgen_data_size = sizeof(*hmacgen_data);
static struct class*  hmac_gen_class  = NULL;
static struct device* hmac_gen_device = NULL;
static int major_num;
DEFINE_MUTEX(hmac_ioctl_lock);

static int dev_open(struct inode *inod, struct file *fil)
{
        printk(KERN_INFO "%s device opened", DEVICE_NAME);
        return 0;
}

static ssize_t dev_read(struct file *filep,char *buf,size_t len,loff_t *off)
{
	int ret = -EINVAL;

	printk(KERN_INFO "Read device %s called", DEVICE_NAME);
	if (!filep || !buf || !off) {
		printk(KERN_ERR "Read device called with null buffer or file pointers!!\n");
		return ret;
	}
	ret = hmac_gen_hash(hmacgen_data);
	if (ret) {
		printk(KERN_ERR "Failed to generate hmac sha with error %d\n", ret);
		return ret;
	}
	if (copy_to_user(buf, hmacgen_data->hash_output, hmacgen_data->olen)) {
		printk(KERN_ERR "Failed to copy the hash output to user\n");
		return -EFAULT;
	}
        return ret;
}

static ssize_t dev_write(struct file *flip,const char *buf,size_t len,loff_t *off)
{
        return -EINVAL;
}

static int dev_release(struct inode *inod,struct file *fil){
        printk(KERN_INFO "KERN_ALERT device closed\n");
        return 0;
}

static long hmac_gen_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	char key[KEY_SIZE];
	char path[1024];
	int algo = -1;
	int klen = 0;

	mutex_lock(&hmac_ioctl_lock);
	switch(cmd) {
		case IOCTL_SET_KEY:
			if (copy_from_user(key, (char *) arg, sizeof(key))) {
				printk(KERN_ERR "Failed to copy key from user\n");
				ret = -ENOMEM;
				break;
			}
			klen = strlen(key);
			if (klen < 0 || klen > KEY_SIZE) {
				printk(KERN_ERR "invalid key size: %d, valid range (0 to %d)\n", klen, KEY_SIZE);
				ret = -EINVAL;
				break;
			}
			ret = hmac_gen_set_key(key, klen);
			break;
		case IOCTL_SET_ALGO:
			if (copy_from_user(&algo, (int *)arg, sizeof(algo))) {
				printk(KERN_ERR "Failed to copy algo from user\n");
				ret = -ENOMEM;
				break;
			}
			ret = hmac_gen_set_algo(algo, hmacgen_data);
			break;
		case IOCTL_SET_FILEPATH:
			if (copy_from_user(path, (char *)arg, sizeof(path))) {
				printk(KERN_ERR "Failed to copy file path from user\n");
				ret = -ENOMEM;
				break;
			}
			ret = hmac_gen_set_filepath(path);
			break;
	}
	mutex_unlock(&hmac_ioctl_lock);
	return ret;
}

static struct file_operations fops=
{
        .read=dev_read,
        .write=dev_write,
        .open=dev_open,
        .release=dev_release,
        .unlocked_ioctl=hmac_gen_ioctl,
};

static int __init hmac_gen_init(void)
{
	int err;
	printk(KERN_INFO "Entering HMAC gen\n");

	printk(KERN_INFO "Calling register dev\n");
	major_num = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_num < 0 ){
		kfree(hmacgen_data);
		printk(KERN_ALERT "device registration failed. %d\n", major_num);
	}
	printk(KERN_INFO "Device %s registration success with major number %d\n",DEVICE_NAME, major_num);

	hmac_gen_class = class_create(THIS_MODULE, "hmac_gen");
	if (IS_ERR(hmac_gen_class)) {
		printk(KERN_ALERT "Failed to register device class \n");
		err = PTR_ERR(hmac_gen_class);
		goto error;
	}
	printk(KERN_INFO "hmac_gen: device class registered successfully \n");

	hmac_gen_device = device_create(hmac_gen_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
	if (IS_ERR(hmac_gen_device)) {
		class_destroy(hmac_gen_class);
		err = PTR_ERR(hmac_gen_device);
		goto error;
	}
	printk(KERN_INFO "hmac_gen: device class created successfully \n");

	hmacgen_data = devm_kzalloc(hmac_gen_device, hmacgen_data_size, GFP_KERNEL);
	if (!hmacgen_data) {
		printk(KERN_ERR "Failed to allocate memory for hmac gen data\n");
		err = -ENOMEM;
		goto error;
	}

	err = hmac_gen_crypto_module_init(hmac_gen_device);
	if (err) {
		printk(KERN_ERR "Failed to initialize hmac gen crypto module\n");
		goto error;
	}

	return err;
error:
	unregister_chrdev(major_num, DEVICE_NAME);
	return err;
}

static void __exit hmac_gen_exit(void)
{
	printk(KERN_INFO "Leaving HMAC gen\n");
	device_destroy(hmac_gen_class, MKDEV(major_num, 0));
	class_unregister(hmac_gen_class);
	class_destroy(hmac_gen_class);
	unregister_chrdev(major_num, DEVICE_NAME);
}

module_init(hmac_gen_init);
module_exit(hmac_gen_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("VMware Photon OS : Keerthana K <keerthanak@vmware.com>");
