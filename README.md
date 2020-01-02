# Ldpinch Unpacker

Unpacker example for the Ldpinch malware.

Tested with the Ldpinch sample with the SHA256: cc65200e7c748e095f65a8d22ecf8618257cc1b2163e1f9df407a0a47ae17b79

For more information see the blog post about unpacking Ldpinch: [Unpacking 101: Writing a static Unpacker for Ldpinch](https://www.gdatasoftware.com/blog/2019/01/31413-unpack-lpdinch-malware)

## Usage

You can find a version of the unpacker written in *C* and one in *Rust* in the repository.

### Rust Version

```bash
> ./ldpinch_unpacker
LdpInch Unpacker 1.0.0
Unpack LdpInch malware.

USAGE:
    ldpinch_unpacker [OPTIONS] -i <input>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i <input>         LdpInch file to unpack.
    -o <output>        Unpacked output file. [default: unpacked.bin]
```

### C Version

```bash
> ./ldpinch_unpacker
LDPINCH Unpacker\nUsage: ldpinch_unpacker [input] [output]
```

Like the *Rust* version, the *C* version has a default `output` value set to `unpacked.bin`.

## Build

The *Rust* version can be easily build with:

```bash
cargo build --release
```
