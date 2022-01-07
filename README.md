# Home Assignment #2
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

The ability to use the `sname` and the `file` fields as options is not supported.

The client has been verified against a real Apple AirPort Express router.

#### Notes

Rust's stdlib has no API for working with raw sockets, so a third-party crate must be used. I used `pnet`: it allows capturing Ethernet frames, but we then have to "unwrap" them payload by payload. It also means that we have to manually wrap our DHCP messages with UDP, Ipv4 and Ethernet packets one after another before we can finally send it somewhere.

The _DHCP Message Type_ option must always be present. This is the way DHCP messages are identified and not misinterpreted as BOOTP messages.

The second client request - `DHCPREQUEST` - must contain the _Requested IP address_ and the _Server identifier_ options. _Requested IP address_ must contain the value of the `yiaddr` field (and the client request must leave this field 0). _Server identifier_ must contain the IP address of the DHCP server (the server's `DHCPOFFER` contains such an option, we can easily take it from there).

The server's `DHCPACK` contains 3 key options: the _Renewal time value_ < the _Rebinding time value_ < the _IP address lease time_.

The client renewal `DHCPREQUEST` must include the _Server identifier_. This message may be both broadcasted or sent directly to the server according to their mac & ip addresses.

So, in total the must-support options are:
- _Pad_
- _Server identifier_
- _Requested IP address_
- _Renewal time value_
- _Rebinding time value_
- _IP address lease time_
- _End_

My other devices use the _Pad_ option to fill the options field until its size is aligned within 16 bytes, and so does this client.

## Links

* Formal requirements: https://insysnw.github.io/practice/hw/udp-real-protocol/
* TFTP RFC1350: https://datatracker.ietf.org/doc/html/rfc1350
* About NetAscii: https://stackoverflow.com/questions/10936478/handling-netascii-in-java
* DHCP RFC2131: https://datatracker.ietf.org/doc/html/rfc2131
* BOOTP Vendor Extensions (options format): https://datatracker.ietf.org/doc/html/rfc1497
* List of all DHCP options: https://datatracker.ietf.org/doc/html/rfc2132
* BOOTP RFC951 (message format): https://datatracker.ietf.org/doc/html/rfc951
