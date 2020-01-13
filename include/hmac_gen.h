/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License version 2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the LICENSE file of this distribution.
 */

int hmac_gen_crypto_module_init(struct device* hmac_gen_device);
int hmac_gen_hash(hmacgen_out_data *user_data);
int hmac_gen_set_key(unsigned char text_key[], int klen);
int hmac_gen_set_algo(int algo, hmacgen_out_data *user_data);
int hmac_gen_set_filepath(unsigned char path[]);
