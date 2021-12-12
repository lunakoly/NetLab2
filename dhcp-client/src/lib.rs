pub mod dhcp;

// use std::fs::{File};
// use std::path::{Path};
// use std::io::{Seek, Read, Write};
// use std::net::{UdpSocket, SocketAddr};
// use std::time::{Duration, Instant};
use std::time::{Duration};
use std::thread;

use rand::{Rng};

use shared::{
    Result,
    ErrorKind,
    with_error_report,
    // is_would_block_io_result
};

use shared::shared::{IntoShared, Shared};

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{NetworkInterface, DataLinkSender, DataLinkReceiver};
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

fn get_mac_address(interface: &NetworkInterface) -> Result<MacAddr> {
    match interface.mac {
        Some(that) => {
            Ok(that)
        }
        None => {
            ErrorKind::Configuration {
                message: format!("No mac address found for the interface > {:?}", interface)
            }.into()
        }
    }
}

fn mac_address_to_bytes(mac_address: MacAddr) -> [u8; 6] {
    [
        mac_address.0,
        mac_address.1,
        mac_address.2,
        mac_address.3,
        mac_address.4,
        mac_address.5,
    ]
}

fn mac_address_bytes_to_chaddr(mac_bytes: &[u8; 6]) -> u128 {
    let mut padded_mac = [0u8; 16];

    for it in 0..mac_bytes.len() {
        padded_mac[it] = mac_bytes[it];
    }

    u128::from_be_bytes(padded_mac)
}

enum State {
    Init,
    Selecting,
    Requesting,
    Rebinding,
    Bound,
    Renewing,
    InitReboot,
    Rebooting,
}

struct Context {
    tx: Box<dyn DataLinkSender>,
    mac: MacAddr,
    chaddr_mac: u128,
    xid: u32,
    should_stop: bool,
    state: State,
    received_messages: Shared<Vec<dhcp::Message>>
}

impl Context {
    fn next_message(&mut self) -> Result<Option<dhcp::Message>> {
        let mut lock = self.received_messages.write()?;

        if lock.len() != 0 {
            Ok(Some(lock.remove(0)))
        } else {
            Ok(None)
        }
    }
}

fn handle_init(context: &mut Context) -> Result<()> {
    let discover = dhcp::Message {
        op: dhcp::OperationCode::BootRequest,
        htype: dhcp::Htype::EthernetMac,
        hlen: dhcp::Htype::EthernetMac.hlen(),
        hops: dhcp::CLIENT_HOPS,
        xid: context.xid,
        secs: 0,
        flags: dhcp::Flags {
            b: false,
        },
        ciaddr: 0,
        yiaddr: 0,
        siaddr: 0,
        giaddr: 0,
        chaddr: context.chaddr_mac,
        sname: [0; 64],
        file: [0; 128],
        options: vec![
            dhcp::Option::DhcpMessageType {
                value: dhcp::MessageType::DhcpDiscover,
                // value: dhcp::MessageType::DhcpRequest,
            },
            dhcp::Option::IpAddressLeaseTime {
                time: 30,
            },
        ],
    };

    let disco = dhcp::to_bytes(&discover)?;

    let mut packet_buffer = [0u8; 1500];
    let low_level_packet = packet_builder!(
        packet_buffer,
        ether({
            set_destination => MacAddr::broadcast(),
            set_source => context.mac
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
    //         return ErrorKind::Configuration {
    //             message: format!("Couldn't serialize")
    //         }.into()
    //     }
    // };

    // p.set_source(dhcp::DEFAULT_CLIENT_PORT);
    // p.set_destination(dhcp::DEFAULT_SERVER_PORT);

    // println!("Crafted > {:?}", &p);
    // println!("Bin > {:?}", p.packet());

    match context.tx.send_to(low_level_packet.packet(), None) {
        Some(thing) => {
            println!("Some was returned\n");

            match thing {
                Ok(_) => {
                    println!("All is ok\n");
                }
                Err(error) => {
                    return ErrorKind::Configuration {
                        message: format!("send_to error > {:?}", error)
                    }.into()
                }
            }
        }
        None => {
            println!("None was returned\n");
        }
    }

    context.state = State::Selecting;
    Ok(())
}

fn handle_selecting(context: &mut Context) -> Result<()> {
    let message = match context.next_message()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);
    Ok(())
}

fn handle_requesting(context: &mut Context) -> Result<()> {
    Ok(())
}

fn handle_rebinding(context: &mut Context) -> Result<()> {
    Ok(())
}

fn handle_bound(context: &mut Context) -> Result<()> {
    Ok(())
}

fn handle_renewing(context: &mut Context) -> Result<()> {
    Ok(())
}

fn handle_init_reboot(context: &mut Context) -> Result<()> {
    Ok(())
}

fn handle_rebooting(context: &mut Context) -> Result<()> {
    Ok(())
}

fn process_incomming_udp(
    data: &[u8],
    received_messages: Shared<Vec<dhcp::Message>>,
) -> Result<()> {
    let packet = match UdpPacket::new(data) {
        Some(it) => it,
        None => {
            return ErrorKind::Configuration {
                message: format!("Error > Not enought data for a udp packet")
            }.into()
        }
    };

    // println!("Udp > {:?}\n", packet);

    if packet.get_destination() != dhcp::DEFAULT_CLIENT_PORT {
        return Ok(())
    }

    let message = match dhcp::from_bytes(packet.payload()) {
        Ok(it) => it,
        Err(error) => {
            println!("Error while parsing a DHCP message > {}\n", error);
            return Ok(())
        }
    };

    received_messages.write()?.push(message);
    Ok(())
}

fn process_incomming_icmp(data: &[u8]) -> Result<()> {
    let packet = match IcmpPacket::new(data) {
        Some(it) => it,
        None => {
            return ErrorKind::Configuration {
                message: format!("Error > Not enought data for an icmp packet")
            }.into()
        }
    };

    println!("Icmp > {:?}\n", packet);
    Ok(())
}

fn loop_main(
    mut tx: Box<dyn DataLinkSender>,
    mac: MacAddr,
    xid: u32,
    received_messages: Shared<Vec<dhcp::Message>>,
) -> Result<()> {
    let chaddr_mac = mac_address_bytes_to_chaddr(&mac_address_to_bytes(mac));
    println!("Using chaddr > {:?}\n", &chaddr_mac);

    let mut context = Context {
        tx: tx,
        mac: mac,
        chaddr_mac: chaddr_mac,
        xid: xid,
        should_stop: false,
        state: State::Init,
        received_messages: received_messages,
    };

    while !context.should_stop {
        match context.state {
            State::Init => handle_init(&mut context)?,
            State::Selecting => handle_selecting(&mut context)?,
            State::Requesting => handle_requesting(&mut context)?,
            State::Rebinding => handle_rebinding(&mut context)?,
            State::Bound => handle_bound(&mut context)?,
            State::Renewing => handle_renewing(&mut context)?,
            State::InitReboot => handle_init_reboot(&mut context)?,
            State::Rebooting => handle_rebooting(&mut context)?,
        }

        thread::sleep(Duration::from_millis(16));
    }

    Ok(())
}

fn process_incomming(
    rx: &mut Box<dyn DataLinkReceiver>,
    mac: MacAddr,
    received_messages: Shared<Vec<dhcp::Message>>,
) -> Result<()> {
    let packet = rx.next()?;

    let ethernet_packet = match EthernetPacket::new(packet) {
        Some(it) => it,
        None => {
            println!("Error > Not enought data for an ethernet packet");
            return Ok(())
        }
    };

    let target = ethernet_packet.get_destination();

    if target != mac && target != MacAddr::broadcast() {
        return Ok(())
    }

    println!("Packet > {:?}\n", &packet);
    // println!("Ethernet > {:?}\n", ethernet_packet);

    let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
        Some(it) => it,
        None => {
            println!("Error > Not enought data for an ipv4 packet");
            return Ok(())
        }
    };

    // println!("Ipv4 > {:?}\n", ipv4_packet);

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Udp => {
            process_incomming_udp(ipv4_packet.payload(), received_messages.clone())?;
        }
        IpNextHeaderProtocols::Icmp => {
            // process_incomming_icmp(ipv4_packet.payload())?;
        }
        it => {
            // println!("Uknown > {:?}\n", it);
        }
    }

    Ok(())
}

fn loop_incomming(
    mut rx: Box<dyn DataLinkReceiver>,
    mac: MacAddr,
    received_messages: Shared<Vec<dhcp::Message>>,
) -> Result<()> {
    loop {
        process_incomming(&mut rx, mac, received_messages.clone())?;
    }
}

fn run_threads() -> Result<()> {
    let xid: u32 = rand::thread_rng().gen();

    println!("Using xid > {:?}\n", &xid);

    let interfaces = datalink::interfaces();
    println!("Interfaces > Found {:?}:", interfaces.len());

    for it in &interfaces {
        println!("    {:?}", it);
    }

    println!("");

    // 0 is loopback
    let interface = &interfaces[1];

    let mac = get_mac_address(interface)?;
    println!("Mac address > {:?}\n", &mac);

    let (tx, rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ErrorKind::Configuration {
            message: format!("Unhandled channel type")
        }.into(),
        Err(e) => return ErrorKind::Configuration {
            message: format!("An error occurred when creating the datalink channel: {}", e)
        }.into()
    };

    let messages = vec![].to_shared();
    let cloned_messages = messages.clone();

    thread::spawn(move || {
        with_error_report(|| loop_incomming(rx, mac, cloned_messages))
    });

    loop_main(tx, mac, xid, messages.clone())
}

pub fn start() {
    with_error_report(run_threads);
}
