pub mod dhcp;
pub mod addresses;

use std::net::{Ipv4Addr};
use std::time::{Duration, Instant};
use std::thread;

use rand::{Rng};

use shared::{
    Result,
    with_error_report,
};

use shared::helpers::{report, warning, misconfiguration};
use shared::shared::{IntoShared, Shared};

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkSender, DataLinkReceiver};
use pnet::packet::ethernet::{EthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::udp::{UdpPacket};
use pnet::packet::{Packet};

use pnet::packet::ip::{
    IpNextHeaderProtocols
};

use pnet::util::{MacAddr};

use packet_builder::payload::{PayloadData};

use packet_builder::{*};

enum State {
    Init,
    Selecting,
    Requesting,
    Rebinding,
    Bound,
    Renewing,
    // InitReboot,
    // Rebooting,
}

type ReceivedMessage = dhcp::Message;
type ReceivedMessages = Shared<Vec<ReceivedMessage>>;

struct Context {
    tx: Box<dyn DataLinkSender>,
    mac: MacAddr,
    chaddr_mac: u128,
    xid: u32,
    should_stop: bool,
    state: State,
    received_messages: ReceivedMessages,
    offered_ip_address: u32,
    waiting_start: Instant,
    server_identifier: dhcp::Option,
    renewal_time: Instant,
    rebinding_time: Instant,
    lease_time: Instant,
    retransmission_count: u8,
    last_info_shown: Instant,
}

const WAITING_LIMIT_MS: u64 = 20_000;

impl Context {
    fn is_waiting_too_long(&self) -> bool {
        let time_spent = Instant::now().duration_since(self.waiting_start);
        time_spent > Duration::from_millis(WAITING_LIMIT_MS)
    }

    fn next_message(&mut self) -> Result<Option<ReceivedMessage>> {
        let mut lock = self.received_messages.write()?;

        if lock.len() != 0 {
            Ok(Some(lock.remove(0)))
        } else {
            Ok(None)
        }
    }

    fn next_message_for_us(&mut self) -> Result<Option<ReceivedMessage>> {
        let it = self.next_message()?;

        match &it {
            None => Ok(None),
            Some(thing) => if thing.xid != self.xid {
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
            context.server_identifier.clone(),
            dhcp::Option::IpAddressLeaseTime {
                time: 30,
            },
        ],
    };

    broadcast_message(&request, context)
}

fn process_message(message: &dhcp::Message, context: &mut Context) -> Result<()> {
    for it in &message.options {
        match it {
            dhcp::Option::ServerIdentifier { .. } => {
                context.server_identifier = it.clone();
            }
            dhcp::Option::RebindingTimeValue { time } => {
                context.rebinding_time = Instant::now() + Duration::from_secs(time.clone().into());
            }
            dhcp::Option::RenewalTimeValue { time } => {
                context.renewal_time = Instant::now() + Duration::from_secs(time.clone().into());
            }
            dhcp::Option::IpAddressLeaseTime { time } => {
                context.lease_time = Instant::now() + Duration::from_secs(time.clone().into());
            }
            _ => {}
        }
    }

    Ok(())
}

fn handle_selecting(context: &mut Context) -> Result<()> {
    if context.is_waiting_too_long() {
        context.state = State::Init;
        return report("Timeout, repeating the discovery.\n");
    }

    let message = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = dhcp::extract_message_type(&message);

    if !matches!(message_type, Some(dhcp::MessageType::DhcpOffer)) {
        // Ignore
        return Ok(())
    }

    process_message(&message, context)?;

    context.offered_ip_address = message.yiaddr;

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

    let message = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = dhcp::extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        context.state = State::Init;
        return report("DHCPNAK > Restarting the procedure!\n");
    }

    if !matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        // Ignore
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
        context.state = State::Rebinding;
        send_renewing_request(context)?;
        return report("T2 expired.\n");
    }

    let now = Instant::now();
    let time_since_last_info = now - context.last_info_shown;

    if time_since_last_info >= Duration::from_secs(1) {
        println!("Time before rebinding > {} sec\n", (context.rebinding_time - now).as_secs());
        context.last_info_shown = now;
    }

    let message = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = dhcp::extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        context.state = State::Init;
        return report("DHCPNAK > Restarting the procedure!\n");
    }

    if matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        context.state = State::Bound;
        process_message(&message, context)?;
        return report("DHCPACK > Updated!\n");
    }

    Ok(())
}

fn handle_rebinding(context: &mut Context) -> Result<()> {
    if context.lease_time < Instant::now() {
        context.state = State::Init;
        return report("DHCPNAK > Lease expired, restarting.\n");
    }

    let now = Instant::now();
    let time_since_last_info = now - context.last_info_shown;

    if time_since_last_info >= Duration::from_secs(1) {
        println!("Time before init > {} sec\n", (context.lease_time - now).as_secs());
        context.last_info_shown = now;
    }

    let message = match context.next_message_for_us()? {
        Some(it) => it,
        None => return Ok(())
    };

    println!("Got a message > {:?}\n", message);

    let message_type = dhcp::extract_message_type(&message);

    if matches!(message_type, Some(dhcp::MessageType::DhcpNak)) {
        context.state = State::Init;
        return report("DHCPNAK > Restarting.\n");
    }

    if matches!(message_type, Some(dhcp::MessageType::DhcpAck)) {
        context.state = State::Bound;
        process_message(&message, context)?;
        return report("DHCPACK > Updating!\n");
    }

    Ok(())
}

fn loop_main(
    tx: Box<dyn DataLinkSender>,
    mac: MacAddr,
    received_messages: ReceivedMessages,
) -> Result<()> {
    let chaddr_mac = addresses::mac_address_to_chaddr(mac);
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
    };

    while !context.should_stop {
        match context.state {
            State::Init => handle_init(&mut context)?,
            State::Selecting => handle_selecting(&mut context)?,
            State::Requesting => handle_requesting(&mut context)?,
            State::Rebinding => handle_rebinding(&mut context)?,
            State::Bound => handle_bound(&mut context)?,
            State::Renewing => handle_renewing(&mut context)?,
        }

        thread::sleep(Duration::from_millis(16));
    }

    Ok(())
}

fn process_incomming(
    rx: &mut Box<dyn DataLinkReceiver>,
    mac: MacAddr,
    received_messages: ReceivedMessages,
) -> Result<()> {
    let packet = rx.next()?;

    let ethernet_packet = match EthernetPacket::new(packet) {
        Some(it) => it,
        None => return warning("Not enought data for an ethernet packet")
    };

    let target = ethernet_packet.get_destination();

    if target != mac && target != MacAddr::broadcast() {
        return Ok(())
    }

    let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
        Some(it) => it,
        None => return warning("Not enought data for an ipv4 packet")
    };

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Udp => {},
        _ => return Ok(())
    };

    let udp_packet = match UdpPacket::new(ipv4_packet.payload()) {
        Some(it) => it,
        None => return misconfiguration("Not enought data for a udp packet")
    };

    if udp_packet.get_destination() != dhcp::DEFAULT_CLIENT_PORT {
        return Ok(())
    }

    let message = match dhcp::from_bytes(udp_packet.payload()) {
        Ok(it) => it,
        Err(error) => return warning(&format!("Error while parsing a DHCP message > {}\n", error))
    };

    received_messages.write()?.push(message);
    Ok(())
}

fn loop_incomming(
    mut rx: Box<dyn DataLinkReceiver>,
    mac: MacAddr,
    received_messages: ReceivedMessages,
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

    let mac = addresses::get_mac_address(interface)?;
    println!("Mac address > {:?}\n", &mac);

    let (tx, rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return misconfiguration("Unhandled channel type"),
        Err(e) => return misconfiguration(
            &format!("An error occurred when creating the datalink channel: {}", e)
        )
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
