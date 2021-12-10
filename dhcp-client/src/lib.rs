pub mod dhcp;

// use std::fs::{File};
// use std::path::{Path};
// use std::io::{Seek, Read, Write};
// use std::net::{UdpSocket, SocketAddr};
// use std::time::{Duration, Instant};

use rand::{Rng};

// use shared::{
//     Result,
//     ErrorKind,
//     with_error_report,
//     is_would_block_io_result
// };

// use shared::shared::{IntoShared, Shared};

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::{IcmpPacket, MutableIcmpPacket};
use pnet::packet::{Packet};

use pnet::packet::ip::{
    IpNextHeaderProtocol,
    IpNextHeaderProtocols
};

use pnet::util::{MacAddr};

use packet_builder::payload::{PayloadData};

use packet_builder::{
    *
    // packet_builder,
    // sub_builder,
    // extract_address,
    // ether,
    // ipv4,
    // ipv4addr,
    // udp,
    // payload,
};

pub fn start() {
    println!("Start\n");

    let mut rng = rand::thread_rng();
    let xid: u32 = rng.gen();

    println!("xid > {:?}\n", &xid);

    let interfaces = datalink::interfaces();
    println!("Interfaces > {:?}\n", interfaces);

    let interface = &interfaces[1];

    let mac_addr = match interface.mac {
        Some(that) => {
            that
        }
        None => {
            println!("No mac address");
            return;
        }
    };

    // let mac_addr = match mac_address::get_mac_address() {
    //     Ok(it) => match it {
    //         Some(that) => {
    //             that
    //         }
    //         None => {
    //             println!("No mac address");
    //             return;
    //         }
    //     }
    //     Err(error) => {
    //         println!("Couldn't get the mac address > {}", error);
    //         return;
    //     }
    // };

    let mac_bytes = [
        mac_addr.0,
        mac_addr.1,
        mac_addr.2,
        mac_addr.3,
        mac_addr.4,
        mac_addr.5,
    ];
    // let mac_bytes = mac_addr.bytes();

    println!("mac bytes > {:?}\n", &mac_bytes);

    let mut padded_mac = [0u8; 16];

    for it in 0..mac_bytes.len() {
        padded_mac[10 + it] = mac_bytes[it];
    }

    println!("Using mac > {:?}\n", &padded_mac);

    let mac = u128::from_be_bytes(padded_mac);

    let discover = dhcp::Message {
        op: dhcp::OperationCode::BootRequest,
        htype: dhcp::Htype::EthernetMac,
        hlen: dhcp::Htype::EthernetMac.hlen(),
        hops: dhcp::CLIENT_HOPS,
        xid: xid,
        secs: 0,
        flags: dhcp::Flags {
            b: true,
        },
        ciaddr: 0,
        yiaddr: 0,
        siaddr: 0,
        giaddr: 0,
        chaddr: mac,
        sname: [0; 64],
        file: [0; 128],
        options: vec![
            dhcp::Option::IpAddressLeaseTime {
                time: 30,
            },
        ],
    };

    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    let mut disco = match dhcp::to_bytes(&discover) {
        Ok(it) => it,
        Err(error) => {
            println!("Couldn't serialzie > {}", error);
            return;
        }
    };

    // println!("Disco: {:?}", &disco);

    match dhcp::from_bytes(&disco) {
        Ok(it) => {
            // println!("Decoded > {:?}", it);
        }
        Err(error) => {
            println!("Couldn't deserialzie > {}", error);
            return;
        }
    }

    let mut pkt_buf = [0u8; 1500];
    let p = packet_builder!(
        pkt_buf,
        ether({
            set_destination => MacAddr(255,255,255,255,255,255),
            set_source => MacAddr(
                mac_bytes[0],
                mac_bytes[1],
                mac_bytes[2],
                mac_bytes[3],
                mac_bytes[4],
                mac_bytes[5]
            )
        }) /
        ipv4({
            set_source => ipv4addr!("0.0.0.0"),
            set_destination => ipv4addr!("255.255.255.255")
        }) /
        udp({
            set_source => dhcp::DEFAULT_CLIENT_PORT,
            set_destination => dhcp::DEFAULT_SERVER_PORT
        }) /
        payload({
            // "hello".to_string().into_bytes()
            &disco
        })
    );

    // let mut p = match MutableUdpPacket::new(&mut disco) {
    //     Some(it) => it,
    //     None => {
    //         println!("Couldn't serialzie");
    //         return;
    //     }
    // };

    // p.set_source(dhcp::DEFAULT_CLIENT_PORT);
    // p.set_destination(dhcp::DEFAULT_SERVER_PORT);

    println!("Crafted > {:?}", &p);
    println!("Bin > {:?}", p.packet());

    match tx.send_to(p.packet(), None) {
        Some(thing) => {
            println!("Some was returned");

            match thing {
                Ok(_) => {
                    println!("All is ok");
                }
                Err(error) => {
                    println!("send_to error > {:?}", error  );
                    return;
                }
            }
        }
        None => {
            println!("None was returned");
        }
    }

    loop {
        match rx.next() {
            Ok(packet) => {
                println!("Inp > {:?}\n", &packet);

                let packet = match EthernetPacket::new(packet) {
                    Some(it) => it,
                    None => {
                        println!("Not enought data for an ethernet packet");
                        continue
                    }
                };

                println!("Eth > {:?}\n", packet);

                let packet2 = match Ipv4Packet::new(packet.payload()) {
                    Some(it) => it,
                    None => {
                        println!("Not enought data for an ipv4 packet");
                        continue
                    }
                };

                println!("Ipv4 > {:?}\n", packet2);

                match packet2.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        let packet3 = match UdpPacket::new(packet2.payload()) {
                            Some(it) => it,
                            None => {
                                println!("Not enought data for a udp packet");
                                continue
                            }
                        };

                        println!("Udp > {:?}\n", packet3);
                    }
                    IpNextHeaderProtocols::Icmp => {
                        let packet3 = match IcmpPacket::new(packet2.payload()) {
                            Some(it) => it,
                            None => {
                                println!("Not enought data for an icmp packet");
                                continue
                            }
                        };

                        println!("Icmp > {:?}\n", packet3);
                    }
                    it => {
                        println!("Uknown > {:?}\n", it);
                    }
                }

                // // Constructs a single packet, the same length as the the one received,
                // // using the provided closure. This allows the packet to be constructed
                // // directly in the write buffer, without copying. If copying is not a
                // // problem, you could also use send_to.
                // //
                // // The packet is sent once the closure has finished executing.
                // tx.build_and_send(1, packet.packet().len(),
                //     &mut |new_packet| {
                //         let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                //         // Create a clone of the original packet
                //         new_packet.clone_from(&packet);

                //         // Switch the source and destination
                //         new_packet.set_source(packet.get_destination());
                //         new_packet.set_destination(packet.get_source());
                // });
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }

    // with_error_report(run_main_loop);
}
