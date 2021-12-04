# Rust UDP Example
## About

This repository contains sample implementations of some UDP protocols in Rust (a university home assignment).

## Build

```bash
cargo build
```

## Run

```bash
cargo run -p tftp-server
```

Servers are expected to be stopped via `Ctrl-C`.

## Implementations
### TFTP

The repository contains an implementation of a TFTP server (`tftp-server`).

The implementation relies on the [RFC1350](https://datatracker.ietf.org/doc/html/rfc1350) document.
Only the `netascii` and the `octet` modes are supported.

Use the following Windows commands to interact with the server:

```bat
tftp -i <host> GET <file> <name-for-saving-locally>
tftp -i <host> PUT <file>
```

The `-i` option forces the `octet` mode. Otherwise it's `netascii`.

This works on macOS:

```bash
$ tftp <host>
tftp> get <file> <name-for-saving-locally>
tftp> put <file>
```

And switch modes via:

```bash
tftp> ascii
tftp> binary
```

The default is `netascii`.

## Links

* Formal requirements: https://insysnw.github.io/practice/hw/udp-real-protocol/
* TFTP RFC1350: https://datatracker.ietf.org/doc/html/rfc1350
* About NetAscii: https://stackoverflow.com/questions/10936478/handling-netascii-in-java
