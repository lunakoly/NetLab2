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
cargo run -p dhcp-client
```

Both apps are expected to be stopped via `Ctrl-C`.

Use `cargo build -p <package> && sudo target/debug/<package>` to allow an app to bind to a protected port if not already running the code as `root`.

Don't forget to disable your system's network configuration daemons. If you use `NetworkManager` & `wpa_supplicant`, use `systemctl stop NetworkManager && systemctl stop wpa_supplicant`.

Note that by default, a Wi-Fi interface won't allow you to capture random packets from a net you are not connected to (unless you put it into the monitor mode). I used a LAN-cable to verify the DHCP-client works.

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

The `-i` option forces the `octet` mode. Otherwise, it's `netascii`.

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

### DHCP

The repository contains an implementation of a DHCP client (`dhcp-client`).

The implementation relies on the [RFC2131](https://datatracker.ietf.org/doc/html/rfc2131) document.

The implementation is minimal, and therefore only supports the acquisition of an IP address without requesting/recording any additional configuration parameters.

As can be seen in the `lib.rs` file, only the `Init`, `Selecting`, `Requesting`, `Rebinding`, `Bound` and `Renewing` states are supported.

The client has been verified against a real Apple AirPort Express router.

## Links

* Formal requirements: https://insysnw.github.io/practice/hw/udp-real-protocol/
* TFTP RFC1350: https://datatracker.ietf.org/doc/html/rfc1350
* About NetAscii: https://stackoverflow.com/questions/10936478/handling-netascii-in-java
