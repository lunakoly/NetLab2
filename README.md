# Rust UDP Example
## About

This repository contains sample implementations of some UDP protocols in Rust (a university home assignment).

## Build

```bash
cargo build
```

## Run

```bash
cargo run -p <package>
```

Servers are expected to be stopped via `Ctrl-C`.

## Implementations
### TFTP

The repository contains an implementation of a TFTP server (`tftp-server`).

The implementation relies on the [RFC1350](https://datatracker.ietf.org/doc/html/rfc1350) document.
Currently, only the `octet` mode is supported.

Use the following Windows commands to interact with the server:

```bat
tftp -i localhost GET <file> <name-for-saving-locally>
tftp -i localhost PUT <file>
```

The `-i` option forces the `octet` mode.

## Links

* Formal requirements: https://insysnw.github.io/practice/hw/udp-real-protocol/
