/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: GPL v2.0
 *
 * Licensed under the GNU Lesser General Public License version 2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the LICENSE file of this distribution.
 */
#include "hmac_gen_ioctl.h"
#define VECTOR_TYPE_SIZE 20
typedef struct crypto_vector {
        unsigned int algo;
        unsigned int mask;
        char vector_type[VECTOR_TYPE_SIZE];
        int mode; //Encrypt=1 /Decrypt=2
        int count;
        int klen;
        int data_tot_len;
        int iv_len;
        int rlen;
        int olen;
        unsigned char filepath[HMAC_MAX_FILEPATH_LEN];
        unsigned char key[KEY_SIZE];
        unsigned char *iv;
        unsigned char *hash_input;
        unsigned char hash_output[HMAC_MAX_OUT_LEN];
} crypto_vector_t;
int hmac_gen_hash(crypto_vector_t *crypto_data);
int hmac_gen_set_key(crypto_vector_t *crypto_data, unsigned char text_key[], int klen);
int hmac_gen_set_algo(crypto_vector_t *crypto_data, int algo);
int hmac_gen_set_filepath(crypto_vector_t *crypto_data, unsigned char path[]);
