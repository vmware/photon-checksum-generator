

# photon-checksum-generator

Photon-checksum-generator is used for generating hmac shasum(sha256/sha512) of a file.

### Prerequisites

In order to compile this project in Photon, linux-devel package is required.

### Build & Run

To compile both user space and kernel modules from the checkout directory, run the following

```sh
make all
```

You should have the userspace binary (hmacgen) under `user` folder, and kernel module (hmac\_generator.ko) under `kernel` folder.

To load the kernel module, run following

```sh
cd kernel
insmod hmac_generator.ko
```

To generate hmac-shasum for a file, use the built userspace binary as

```sh
cd user
./hmacgen <HMAC-SHA256/HMAC-SHA512> <key> <path-to-the-file>
```

## Contributing

The photon-checksum-generator project team welcomes contributions from the community. Before you start working with photon-checksum-generator, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

