/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: GPL v2.0
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
#include <crypto/algapi.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <linux/namei.h>
#include <asm/byteorder.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#include "../include/hmac_gen.h"

#define DIGEST_SIZE 512
#define TEXT_SIZE (64 * (1024))
#define MAX_FILE_SIZE 256000000 //256 MB

struct ft_crypt_result {
	struct completion completion;
	int err;
};
static DEFINE_MUTEX(hmacgen_crypto_lock);

static void ft_crypt_complete(struct crypto_async_request *req, int err)
{
	struct ft_crypt_result *res = req->data;

	printk(KERN_INFO "pbs: async\n");
	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static void ft_result_init(struct ft_crypt_result *ft)
{
	memset(ft, 0, sizeof(*ft));
	init_completion(&ft->completion);
}

int test_hash(crypto_vector_t *crypto_data)
{
	struct crypto_ahash *tfm = NULL;
	struct ahash_request *req = NULL;
	struct ft_crypt_result ft_result;
	struct scatterlist sgin;
	const char *algo;
	int ret = -ENOMEM;

	tfm = crypto_alloc_ahash(crypto_data->vector_type, crypto_data->algo, crypto_data-> mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: cipher: Failed to load transform for "
			"%s: %ld\n", "cbc(aes)", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	algo = crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm));
	if (algo) {
		printk(KERN_INFO "Algo = %s\n", algo );
	} else {
		printk(KERN_ERR "driver not available\n");
		ret =-EINVAL;
		goto out;
	}

	crypto_ahash_clear_flags(tfm, ~0);
	if (crypto_data->klen) {
		ret = crypto_ahash_setkey(tfm, crypto_data->key, crypto_data->klen);
		if (ret) {
			printk(KERN_ERR "setting hash key err %d \n", ret);
			goto out;
		}
	}

	ft_result_init(&ft_result);
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		printk(KERN_ERR "hash request alloc error \n");
		goto out;
	}

	ahash_request_set_tfm(req, tfm);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				CRYPTO_TFM_REQ_MAY_BACKLOG,
				ft_crypt_complete, &ft_result);

	sg_init_one(&sgin, crypto_data->hash_input, crypto_data->data_tot_len);

	ahash_request_set_crypt(req, &sgin, crypto_data->hash_output, crypto_data->data_tot_len);

	ret = crypto_ahash_digest(req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		ret = wait_for_completion_interruptible_timeout(&ft_result.completion, 10*HZ);
		if (!ret)
			ret = ft_result.err;
	}

	/*crypto_ahash_update() */
	ahash_request_free(req);
out:
	crypto_free_ahash(tfm);
	return ret;
}

int hmac_gen_set_key(crypto_vector_t *crypto_data, unsigned char text_key[KEY_SIZE], int klen)
{

	mutex_lock(&hmacgen_crypto_lock);
	if (klen) {
		strncpy(crypto_data->key, text_key, klen);;
		crypto_data->klen = klen;
	}
	mutex_unlock(&hmacgen_crypto_lock);
	return 0;
}

int hmac_gen_set_algo(crypto_vector_t *crypto_data, int algo)
{
	int ret = 0;

	mutex_lock(&hmacgen_crypto_lock);
	crypto_data->algo = CRYPTO_ALG_TYPE_SHASH;
	crypto_data->mask = 0;
	switch (algo) {
		case HMAC_SHA256:
			strncpy(crypto_data->vector_type, "hmac(sha256)", VECTOR_TYPE_SIZE);
			crypto_data->olen = 32;
			break;
		case HMAC_SHA512:
			strncpy(crypto_data->vector_type, "hmac(sha512)", VECTOR_TYPE_SIZE);
			crypto_data->olen = 64;
			break;
		default:
			printk(KERN_ERR "hash algo not supported");
			ret = -EINVAL;
			break;
	}
	printk(KERN_INFO "Vector type from %s is %s\n",__func__, crypto_data->vector_type);
	mutex_unlock(&hmacgen_crypto_lock);

	return ret;
}

int hmac_gen_set_filepath(crypto_vector_t *crypto_data, unsigned char path[])
{
	mutex_lock(&hmacgen_crypto_lock);
	strncpy(crypto_data->filepath, path, HMAC_MAX_FILEPATH_LEN);
	mutex_unlock(&hmacgen_crypto_lock);
	return 0;
}

int hmac_gen_hash(crypto_vector_t *crypto_data)
{
	int ret = 0;
	enum kernel_read_file_id id = READING_MODULE;
	void *buf = NULL;
	loff_t size;
	size_t msize = INT_MAX;
	struct path path;
	struct kstat stat;

	if(!crypto_data) {
		printk(KERN_ERR "crypto data is NULL\n");
		return -EINVAL;
	}

	mutex_lock(&hmacgen_crypto_lock);

	if (strlen(crypto_data->filepath) == 0) {
		printk(KERN_ERR "File path is not set properly\n");
		ret = -EINVAL;
		goto out;
	}
	if (strlen(crypto_data->key) == 0 || crypto_data->klen == 0) {
		printk(KERN_ERR "Key is not set properly\n");
		ret = -EINVAL;
		goto out;
	}
	if (strncmp(crypto_data->vector_type, "hmac(sha256)", strlen("hmac(sha256)")) && strncmp(crypto_data->vector_type, "hmac(sha512)", strlen("hmac(sha512)"))) {
		printk(KERN_ERR "HMAC strength is not set properly\n");
		ret = -EINVAL;
		goto out;
	}
	ret = kern_path(crypto_data->filepath, 0, &path);
	if (ret) {
		printk(KERN_ERR "kernel path error %s\n",crypto_data->filepath);
		goto out;
	}

	ret = vfs_getattr(&path, &stat, STATX_SIZE, 0);
	if (ret) {
		printk(KERN_ERR "kernel Read file stats Error\n");
		goto out;
	}
	printk(KERN_INFO "File Size = %lld\n", stat.size);

	if (stat.size > MAX_FILE_SIZE) {
		printk(KERN_ERR "File size exceeded\n");
		ret = -EFBIG;
		goto out;
	}

	ret = kernel_read_file_from_path(crypto_data->filepath, &buf, &size,
					msize, id);
	if (ret) {
		printk(KERN_ERR "Loading %s failed with error %d\n", crypto_data->filepath, ret);
		goto out;
	}

	crypto_data->hash_input = buf;
	crypto_data->data_tot_len = size;
	ret = test_hash(crypto_data);
	if (ret) {
		printk(KERN_ERR "test_hash (%s) err %d\n", crypto_data->vector_type, ret);
		goto out;
	}
	crypto_data->hash_output[crypto_data->olen] = '\0';

out:
	if (ret) {
		memset(crypto_data->hash_output, 0, sizeof(*crypto_data->hash_output));
	}
	if (buf != NULL) {
		vfree(buf);
	}
	mutex_unlock(&hmacgen_crypto_lock);
	return ret;
}
