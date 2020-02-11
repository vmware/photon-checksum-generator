/*
 * Copyright 2020 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: GPL v2.0
 *
 * Licensed under the GNU Lesser General Public License version 2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the LICENSE file of this distribution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/stat.h>

#include "hmac_gen_ioctl.h"
#define IsNullOrEmptyString(str) (!(str) || !(*str))
int hmac_fd = -1;
static int olen = 0;
static int hmacgen_read_hash(void);;
static int hmacgen_driver_init(char *hmacgen_device);
static int hmacgen_set_algo(char *strength);
static int hmacgen_set_key(char *key);
static int hmacgen_set_filepath(char *filepath);

int main(int argc, char **argv)
{
	int ret = 1;
	int i = 0;

	if (argc != 4) {
		fprintf(stderr, "Provide complete args\n");
		fprintf(stderr, "Ex: ./hmacgen <hmac-strength> <key> <path-to-file>\n");
		fprintf(stderr, "possible values for hmac-strength: HMAC-SHA256, HMAC-SHA512\n");
		goto cleanup;
	}

	hmac_fd = hmacgen_driver_init(DEVICE_NAME);
	if (hmac_fd < 0) {
		fprintf(stderr, "FATAL open HMAC GEN driver error %d\n", hmac_fd);
		goto cleanup;
	}
	ret = hmacgen_set_algo(argv[1]);
	if (ret) {
		fprintf(stderr, "hmac generation failed in setting hmac strength. Exiting!\n");
		goto cleanup;
	}
	ret = hmacgen_set_key(argv[2]);
	if (ret) {
		fprintf(stderr, "hmac generation failed in setting key. Exiting!\n");
		goto cleanup;
	}
	ret = hmacgen_set_filepath(argv[3]);
	if (ret) {
		fprintf(stderr, "hmac generation failed in setting file path. Exiting!\n");
		goto cleanup;
	}
	ret = hmacgen_read_hash();
	if (ret)
	{
		fprintf(stdout, "hmac generation failed with error %d. Exiting!\n", ret);
		goto cleanup;
	}
cleanup:
	if (hmac_fd > 0) {
		close(hmac_fd);
	}
	return ret;
}

static int hmacgen_driver_init(char *hmacgen_device)
{
	char device_name[50];
	int fd, ret = -1;

	snprintf( device_name, sizeof( device_name ) -1, "/dev/%s", hmacgen_device);
	fd = open( device_name, O_RDWR );

	if( fd < 0 )
	{
		fprintf(stderr, "Failed to open device: %s\n", device_name);
		return -1;
	}
	return fd;
}

static int hmacgen_set_algo(char *strength)
{
	int ret = -1;
	int algo = 0;

	if (strncmp(strength, "HMAC-SHA256", strlen("HMAC-SHA256")) == 0) {
		algo = 1;
		olen = 32;
	}
	else if (strncmp(strength, "HMAC-SHA512", strlen("HMAC-SHA512")) == 0) {
		algo = 2;
		olen = 64;
	}
	else {
		fprintf(stderr, "Invalid value HMAC SHA strength\n");
		return ret;
	}

	ret = ioctl(hmac_fd, IOCTL_SET_ALGO, (int *)&algo);
	if (ret < 0) {
		fprintf(stderr, "Error setting the HMAC strength to hmac_gen driver\n");
	}
	return ret;
}

static int hmacgen_set_key(char *key)
{
	int ret = -1;

	if (IsNullOrEmptyString(key)) {
		fprintf(stderr, "Null or empty key\n");
		return ret;
	}

	ret = ioctl(hmac_fd, IOCTL_SET_KEY, key);
	if (ret < 0) {
		fprintf(stderr, "Error setting the key to hmac_gen driver\n");
	}
	return ret;
}

static int hmacgen_set_filepath(char *filepath)
{
	int ret = -1;
	struct stat file_stats;
	char file_path[HMAC_MAX_FILEPATH_LEN] = {0};

	if(IsNullOrEmptyString(filepath)) {
		fprintf(stderr, "Null or empty file path\n");
		return ret;
	}

	memset(&file_stats, 0, sizeof(struct stat));
	if ( access( filepath, F_OK | R_OK )) {
		ret = -errno;
		return ret;
	}
	if (stat( filepath, &file_stats)) {
		ret = -errno;
		return ret;
	}
	if (file_stats.st_size <= 0) {
		fprintf(stderr, "File size is zero\n");
		return ret;
	}
	strncpy(file_path, filepath, strlen(filepath));
	ret = ioctl(hmac_fd, IOCTL_SET_FILEPATH, file_path);
	if (ret < 0) {
		fprintf(stderr, "Error setting the file path to hmac_gen driver\n");
	}
	return ret;
}

static int hmacgen_read_hash(void)
{
	int ret = -1;
	unsigned char hash_output[HMAC_MAX_OUT_LEN] = {0};
	int i = 0;

	ret = read(hmac_fd, hash_output, HMAC_MAX_OUT_LEN);
	if( ret < 0 )
	{
		fprintf(stderr, "Failed to read hash output from the device\n");
		goto cleanup;
	}
        for ( i = 0; i < olen; i++)
	{
                fprintf(stdout, "%02x",hash_output[i]);
	}
	fprintf(stdout, "\n");
cleanup:
	return ret;
}
