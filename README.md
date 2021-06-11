# Crypt4GH File System (in Rust)

[![Crates.io](https://img.shields.io/crates/v/crypt4ghfs)](https://crates.io/crates/crypt4ghfs)
[![Docs.rs](https://docs.rs/crypt4ghfs/badge.svg)](https://docs.rs/crypt4ghfs/latest/crypt4ghfs)
![GitHub](https://img.shields.io/github/license/EGA-archive/crypt4ghfs-rust)

Crypt4GH FUSE File system in Rust. It allows to encrypt and decrypt crypt4gh files in a directory automatically.

## Installation

> Requirements: [Rust](https://www.rust-lang.org/tools/install)

Supported platforms:

-   **Linux** (tested on Ubuntu 20.04)
-   **macOS** (up to Big Sur, Monterey does not support FUSE yet)

```sh
cargo install crypt4ghfs
```

## Usage

The usage of the command is the following:

```txt
USAGE:
    crypt4ghfs [FLAGS] <MOUNTPOINT> --conf <conf_path>

ARGS:
    <MOUNTPOINT>

FLAGS:
    -h, --help       Prints help information
    -v, --verbose    Sets the level of verbosity
    -V, --version    Prints version information

OPTIONS:
        --conf <conf_path>
```

## Configuration

```toml
[DEFAULT]
# Extensions to be detected as encrypted
extensions = ["c4gh"]

[LOGGER]
# Whether to use syslog or to output to stderr
use_syslog = false
# Level of the logger. Should be one of ["TRACE", "DEBUG", "INFO", "WARN", "CRITICAL"]
log_level = "DEBUG"
# Syslog facility
log_facility = "local2"

[FUSE]
# The options that will be sent to fuse. The following are available:
# "allow_other", "allow_root", "allow_unmount", "default_permissions", "dev", "no_dev", "suid", "no_suid", "ro", "rw", "exec", "no_exec", "atime", "no_atime", "dir_sync", "sync", "async"
options= ["ro", "default_permissions", "allow_other", "auto_unmount"]
# Path to the root directory of the filesystem
rootdir="tests/rootdir"

[CRYPT4GH]
# Path to the public keys of the recipients to encrypt to
recipients = ["tests/testfiles/bob.pub"]
# Include log of the crypt4gh encryption / decryption
include_crypt4gh_log = true
# Include my public key to the recipients (so I can decrypt the file too)
include_myself_as_recipient = true
# Path to my private key
seckey = "tests/configs/bob"
```
