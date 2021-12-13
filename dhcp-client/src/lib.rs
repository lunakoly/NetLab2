pub mod dhcp;

// use std::fs::{File};
// use std::path::{Path};
// use std::io::{Seek, Read, Write};
use std::net::{Ipv4Addr};
use std::time::{Duration, Instant};
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
    received_messages: Shared<Vec<(dhcp::Message, MacAddr)>>,
    offered_ip_address: u32,
    waiting_start: Instant,
    server_identifier: dhcp::Option,
    renewal_time: Instant,
    rebinding_time: Instant,
    lease_time: Instant,
    retransmission_count: u8,
    last_info_shown: Instant,
    server_mac: MacAddr,
}

const WAITING_LIMIT_MS: u64 = 20_000;

impl Context {
    fn is_waiting_too_long(&self) -> bool {
        let time_spent = Instant::now().duration_since(self.waiting_start);
        time_spent > Duration::from_millis(WAITING_LIMIT_MS)
    }

    fn next_message(&mut self) -> Result<Option<(dhcp::Message, MacAddr)>> {
        let mut lock = self.received_messages.write()?;

        if lock.len() != 0 {
            Ok(Some(lock.remove(0)))
        } else {
            Ok(None)
        }
    }

    fn next_message_for_us(&mut self) -> Result<Option<(dhcp::Message, MacAddr)>> {
        let it = self.next_message()?;

        match &it {
            None => Ok(None),
            Some(thing) => if thing.0.xid != self.xid {
                Ok(None)
            } else {
                Ok(it)
            }
        }
    }
}

fn send_message(
    message: &dhcp::Message,
    ethernet_destination: MacAddr,
    ipv4_source: Ipv4Addr,
    ipv4_destination: Ipv4Addr,
    context: &mut Context,
) -> Result<()> {
    let message_bytes = dhcp::to_bytes(&message)?;

    let mut packet_buffer = [0u8; 1500];
    let low_level_packet = packet_builder!(
        packet_buffer,
        ether({
            set_destination => ethernet_destination,
            set_source => context.mac
        }) /
        ipv4({
            set_source => ipv4_source,
            set_destination => ipv4_destination
        }) /
        udp({
            set_source => dhcp::DEFAULT_CLIENT_PORT,
            set_destination => dhcp::DEFAULT_SERVER_PORT
        }) /
        payload({
            &message_bytes
        })
    );

    match context.tx.send_to(low_level_packet.packet(), None) {
        Some(thing) => {
            thing?;
        }
        None => {
            println!("None was returned\n");
        }
    }

    context.waiting_start = Instant::now();
    Ok(())
}

fn broadcast_message(message: &dhcp::Message, context: &mut Context) -> Result<()> {
    send_message(
        message,
        MacAddr::broadcast(),
        ipv4addr!("0.0.0.0"),
        ipv4addr!("255.255.255.255"),
        context
    )
}

fn send_discover(context: &mut Context) -> Result<()> {
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
            },
            dhcp::Option::IpAddressLeaseTime {
                time: 30,
            },
        ],
    };

    broadcast_message(&discover, context)
}

fn handle_init(context: &mut Context) -> Result<()> {
    context.xid = rand::thread_rng().gen();

    println!("Using xid > {:?}\n", &context.xid);

    send_discover(context)?;

    context.state = State::Selecting;
    Ok(())
}

fn send_request(context: &mut Context) -> Result<()> {
    let request = dhcp::Message {
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
                value: dhcp::MessageType::DhcpRequest,
            },
            dhcp::Option::IpAddressLeaseTime {
                time: 30,
            },
            context.server_identifier.clone(),
            dhcp::Option::RequestedIpAddress {
                address: context.offered_ip_address,
            }
        ],
    };

    broadcast_message(&request, context)
}

fn send_renewing_request(context: &mut Context) -> Result<()> {
    let request = dhcp::Message {
        op: dhcp::OperationCode::BootRequest,
        htype: dhcp::Htype::EthernetMac,
        hlen: dhcp::Htype::EthernetMac.hlen(),
        hops: dhcp::CLIENT_HOPS,
        xid: context.xid,
        secs: 0,
        flags: dhcp::Flags {
            b: false,
        },
        ciaddr: context.offered_ip_address,
        yiaddr: 0,
        siaddr: 0,
        giaddr: 0,
        chaddr: context.chaddr_mac,
        sname: [0; 64],
        file: [0; 128],
        options: vec![
            dhcp::Option::DhcpMessageType {
                value: dhcp::MessageType::DhcpRequest,
            },
            // dhcp::Option::IpAddressLeaseTime {
            //     time: 30,
            // },
            // dhcp::Option::RequestedIpAddress {
            //     address: context.offered_ip_address,
            // }
        ],
    };

    let source = context.offered_ip_address.into();

    let destination = match context.server_identifier {
        dhcp::Option::ServerIdentifier { address } => {
            address.into()
        }
        _ => Ipv4Addr::BROADCAST
    };

    send_message(&request, context.server_mac, source, destination, context)
}

fn extract_message_type(message: &dhcp::Message) -> Option<dhcp::MessageType> {
    for it in &message.options {
        match it {
            dhcp::Option::DhcpMessageType { value } => {
                return Some(value.clone());
            }
            _ => {}
        }
    }

    None
}

fn process_message(message: &dhcp::Message, context: &mut Context) -> Result<()> {
    for it in &message.options {
        match it {
            dhcp::Option::ServerIdentifier { .. } => {
                context.server_identifier = it.clone();
            }
            dhcp::Option::RebindingTimeValue { time } => {
                context.rebinding_time = Instant::now() + Duration::from_secs(time.clone().into());
                // context.rebinding_time = Instant::now() + Duration::from_secs(10);
            }
            dhcp::Option::RenewalTimeValue { time } => {
                // context.renewal_time = Instant::now() + Duration::from_secs(time.clone().into());
                context.renewal_time = Instant::now() + Duration::from_secs(5);
            }
            dhcp::Option::IpAddressLeaseTime { time } => {
                context.lease_time = Instant::now() + Duration::from_secs(time.clone().into());
                // context.lease_time = Instant::now() + Duration::from_secs(15);
            }
            _ => {}
        }
    }

    Ok(())
}

fn handle_selecting(context: &mut Context) -> Result<()> {
    if context.is_waiting_too_long() {
        println!("Timeout, repeating the discovery.\n");
        context.state = State::Init;
        return Ok(())
    }

    let (message, sender_mac) = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = extract_message_type(&message);

    if !matches!(message_type, Some(dhcp::MessageType::DhcpOffer)) {
        // ignore
        return Ok(())
    }

    process_message(&message, context)?;

    context.offered_ip_address = message.yiaddr;
    context.server_mac = sender_mac;

    let server = match context.server_identifier {
        dhcp::Option::ServerIdentifier { address } => {
            address.to_be_bytes().map(|it| format!("{:?}", it)).join(".")
        }
        _ => "Unknown".to_owned()
    };

    println!("Bound to server > {}\n", server);

    let ip_address = context.offered_ip_address
        .to_be_bytes()
        .map(|it| format!("{:?}", it))
        .join(".");

    println!("Offered IP > {}\n", ip_address);

    send_request(context)?;

    context.retransmission_count = 0;
    context.state = State::Requesting;
    Ok(())
}

fn handle_requesting(context: &mut Context) -> Result<()> {
    if context.is_waiting_too_long() {
        context.retransmission_count += 1;

        if context.retransmission_count >= 5 {
            println!("Timeout, too many tries, restarting.\n");
            context.state = State::Init;
        } else {
            println!("Timeout, repeating the request.\n");
            send_request(context)?;
        }

        return Ok(())
    }

    let (message, _) = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        println!("DHCPNAK > Restarting the procedure!\n");
        context.state = State::Init;
        return Ok(())
    }

    if !matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        // ignore
        return Ok(())
    }

    process_message(&message, context)?;

    println!("Acknoledged.\n");
    println!("Renewal time > {} sec\n", (context.renewal_time - Instant::now()).as_secs());
    println!("Rebinding time > {} sec\n", (context.rebinding_time - Instant::now()).as_secs());
    println!("Lease time > {} sec\n", (context.lease_time - Instant::now()).as_secs());

    context.state = State::Bound;

    Ok(())
}

fn handle_bound(context: &mut Context) -> Result<()> {
    let now = Instant::now();
    let time_since_last_info = now - context.last_info_shown;

    if context.renewal_time > now {
        if time_since_last_info >= Duration::from_secs(1) {
            println!("Time before renewal > {} sec\n", (context.renewal_time - now).as_secs());
            context.last_info_shown = now;
        }

        return Ok(())
    }

    println!("T1 expired.\n");

    send_renewing_request(context)?;

    context.state = State::Renewing;
    Ok(())
}

fn handle_renewing(context: &mut Context) -> Result<()> {
    if context.rebinding_time < Instant::now() {
        println!("T2 expired.\n");
        send_renewing_request(context)?;
        context.state = State::Rebinding;
        return Ok(())
    }

    let now = Instant::now();
    let time_since_last_info = now - context.last_info_shown;

    if time_since_last_info >= Duration::from_secs(1) {
        println!("Time before rebinding > {} sec\n", (context.rebinding_time - now).as_secs());
        context.last_info_shown = now;
    }

    let (message, _) = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        println!("DHCPNAK > Restarting the procedure!\n");
        context.state = State::Init;
        return Ok(())
    }

    if matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        println!("DHCPACK > Updating!\n");
        process_message(&message, context)?;
        context.state = State::Bound;
        return Ok(())
    }

    Ok(())
}

fn handle_rebinding(context: &mut Context) -> Result<()> {
    if context.lease_time < Instant::now() {
        println!("DHCPNAK > Lease expired, restarting.\n");
        context.state = State::Init;
        return Ok(())
    }

    let now = Instant::now();
    let time_since_last_info = now - context.last_info_shown;

    if time_since_last_info >= Duration::from_secs(1) {
        println!("Time before init > {} sec\n", (context.lease_time - now).as_secs());
        context.last_info_shown = now;
    }

    let (message, _) = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        println!("DHCPNAK > Restarting.\n");
        context.state = State::Init;
        return Ok(())
    }

    if matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        println!("DHCPACK > Updating!\n");
        process_message(&message, context)?;
        context.state = State::Bound;
        return Ok(())
    }

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
    received_messages: Shared<Vec<(dhcp::Message, MacAddr)>>,
    sender_mac: MacAddr,
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

    received_messages.write()?.push((message, sender_mac));
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
    received_messages: Shared<Vec<(dhcp::Message, MacAddr)>>,
) -> Result<()> {
    let chaddr_mac = mac_address_bytes_to_chaddr(&mac_address_to_bytes(mac));
    println!("Using chaddr > {:?}\n", &chaddr_mac);

    let mut context = Context {
        tx: tx,
        mac: mac,
        chaddr_mac: chaddr_mac,
        xid: 0,
        should_stop: false,
        state: State::Init,
        received_messages: received_messages,
        offered_ip_address: 0,
        waiting_start: Instant::now(),
        server_identifier: dhcp::Option::Pad,
        rebinding_time: Instant::now(),
        renewal_time: Instant::now(),
        lease_time: Instant::now(),
        retransmission_count: 0,
        last_info_shown: Instant::now(),
        server_mac: MacAddr::broadcast(),
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
    received_messages: Shared<Vec<(dhcp::Message, MacAddr)>>,
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

    // println!("Packet > {:?}\n", &packet);
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
            process_incomming_udp(
                ipv4_packet.payload(),
                received_messages.clone(),
                ethernet_packet.get_source(),
            )?;
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
    received_messages: Shared<Vec<(dhcp::Message, MacAddr)>>,
) -> Result<()> {
    loop {
        process_incomming(&mut rx, mac, received_messages.clone())?;
    }
}

fn run_threads() -> Result<()> {
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

    loop_main(tx, mac, messages.clone())
}

pub fn start() {
    with_error_report(run_threads);
}
