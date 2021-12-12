pub mod persistency;
pub mod addresses;

use std::io::{Write};

use shared::{Result, ErrorKind};
use shared::helpers::caret::{Caret};

use shared::{take};

use shared::serialization::{
    serialize_u8,
    deserialize_u8,
    serialize_u16,
    deserialize_u16,
    serialize_u32,
    deserialize_u32,
    serialize_u128,
    deserialize_u128,
};

#[derive(Debug, Clone)]
pub enum Htype {
    EthernetMac,
}

impl Htype {
    pub fn hlen(&self) -> u8 {
        match self {
            Htype::EthernetMac => 6,
        }
    }
}

pub const CLIENT_HOPS: u8 = 0x00;

#[derive(Debug, Clone)]
pub enum OperationCode {
    BootRequest,
    BootReply,
}

#[derive(Debug, Clone)]
pub struct Flags {
    pub b: bool,
}

impl Flags {
    // pub fn b(&self) -> bool {
    //     (self.inner & (1 << 15)) != 0
    // }
}

#[derive(Debug, Clone)]
pub enum MessageType {
    DhcpDiscover,
    DhcpOffer,
    DhcpRequest,
    DhcpDecline,
    DhcpAck,
    DhcpNak,
    DhcpRelease,
    DhcpInform,
}

impl MessageType {
    fn to_number(&self) -> u8 {
        match self {
            MessageType::DhcpDiscover => 1,
            MessageType::DhcpOffer => 2,
            MessageType::DhcpRequest => 3,
            MessageType::DhcpDecline => 4,
            MessageType::DhcpAck => 5,
            MessageType::DhcpNak => 6,
            MessageType::DhcpRelease => 7,
            MessageType::DhcpInform => 8,
        }
    }

    fn from_number(it: u8) -> Result<MessageType> {
        match it {
            1 => Ok(MessageType::DhcpDiscover),
            2 => Ok(MessageType::DhcpOffer),
            3 => Ok(MessageType::DhcpRequest),
            4 => Ok(MessageType::DhcpDecline),
            5 => Ok(MessageType::DhcpAck),
            6 => Ok(MessageType::DhcpNak),
            7 => Ok(MessageType::DhcpRelease),
            8 => Ok(MessageType::DhcpInform),
            _ => ErrorKind::UnsupportedFormat {
                message: format!("Uknown DHCP Message Type > {}", it)
            }.into()
        }
    }
}

#[derive(Debug, Clone)]
pub enum Option {
    Pad,
    SubnetMask { mask: u32 },
    // Router { addresses: Vec<u32> },
    // DomainNameServer { addresses: Vec<u32> },
    // StaticRoutingTable { map: Vec<(u32, u32)> },
    RequestedIpAddress { address: u32 },
    IpAddressLeaseTime { time: u32 },
    DhcpMessageType { value: MessageType },
    ServerIdentifier { address: u32 },
    RenewalTimeValue { time: u32 },
    RebindingTimeValue { time: u32 },
    // ParameterRequestList { codes: Vec<u8> },
    // ClassIdentifier { info: Vec<u8> },
    // ClientIdentifier { value: Vec<u8> },
    // BootfileName { value: Vec<u8> },
    // ClasslessStaticRouteOption { routes: Vec<(Vec<u8>, u32)> },
    End,
    Other { code: u8, data: Vec<u8> },
}

pub const MIN_OPTIONS_SIZE: usize = 312 * 8;

#[derive(Debug, Clone)]
pub struct Message {
    pub op: OperationCode,
    pub htype: Htype,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: Flags,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: u128,
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<Option>,
}

pub const DEFAULT_SERVER_PORT: u16 = 67;
pub const DEFAULT_CLIENT_PORT: u16 = 68;

fn serialize_op<W: Write>(op: &OperationCode, output: W) -> Result<()> {
    let id = match op {
        OperationCode::BootRequest => 1,
        OperationCode::BootReply => 2,
    };

    serialize_u8(id, output)
}

fn serialize_htype<W: Write>(value: &Htype, output: W) -> Result<()> {
    match value {
        // See: RFC 1700 «Assigned Numbers»
        Htype::EthernetMac => serialize_u8(1, output),
    }
}

fn serialize_flags<W: Write>(flags: &Flags, output: W) -> Result<()> {
    serialize_u16(u16::from(flags.b) << 15, output)
}

fn serialize_option<W: Write>(option: &Option, mut output: W) -> Result<()> {
    match option {
        Option::Pad => {
            serialize_u8(0, &mut output)?;
        }
        Option::SubnetMask { mask } => {
            serialize_u8(1, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(mask.clone(), &mut output)?;
        }
        Option::RequestedIpAddress { address } => {
            serialize_u8(50, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(address.clone(), &mut output)?;
        }
        Option::IpAddressLeaseTime { time } => {
            serialize_u8(51, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(time.clone(), &mut output)?;
        }
        Option::DhcpMessageType { value } => {
            serialize_u8(53, &mut output)?;
            serialize_u8(1, &mut output)?;
            serialize_u8(value.to_number(), &mut output)?;
        }
        Option::ServerIdentifier { address } => {
            serialize_u8(54, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(address.clone(), &mut output)?;
        }
        Option::RenewalTimeValue { time } => {
            serialize_u8(58, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(time.clone(), &mut output)?;
        }
        Option::RebindingTimeValue { time } => {
            serialize_u8(59, &mut output)?;
            serialize_u8(4, &mut output)?;
            serialize_u32(time.clone(), &mut output)?;
        }
        Option::End => {
            serialize_u8(255, &mut output)?;
        }
        Option::Other { code, data } => {
            serialize_u8(code.clone(), &mut &mut output)?;
            output.write_all(data)?;
        }
        // Option::SubnetMask { mask } => {
        //     serialize_u8(1, output)?;
        //     serialize_u32(mask.clone(), output)?;
        // }
        // Option::Router { addresses } => {
        //     serialize_u8(3, output)?;

        // },
        // Option::DomainNameServer => 6,
        // Option::StaticRoutingTable => 33,
        // Option::IpAddressLeaseTime => 51,
        // Option::DhcpMessageType => 53,
        // Option::ParameterRequestList => 55,
        // Option::ClassIdentifier => 60,
        // Option::ClientIdentifier => 61,
        // Option::TftpServerName => 66,
        // Option::BootfileName => 67,
        // Option::ClasslessStaticRouteOption => 121,
        // Option::TftpServerAddress => 150,
        // Option::End => 255,
        // Option::Other { code } => code.clone(),
    }

    Ok(())
}

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

fn serialize_options<W: Write>(options: &[Option], mut output: W) -> Result<()> {
    output.write_all(&MAGIC_COOKIE)?;

    for it in options {
        serialize_option(it, &mut output)?;
    }

    serialize_option(&Option::End, &mut output)
}

pub fn to_bytes(message: &Message) -> Result<Vec<u8>> {
    let mut buffer = vec![];

    serialize_op(&message.op, &mut buffer)?;
    serialize_htype(&message.htype, &mut buffer)?;
    serialize_u8(message.hlen, &mut buffer)?;
    serialize_u8(message.hops, &mut buffer)?;
    serialize_u32(message.xid, &mut buffer)?;
    serialize_u16(message.secs, &mut buffer)?;
    serialize_flags(&message.flags, &mut buffer)?;
    serialize_u32(message.ciaddr, &mut buffer)?;
    serialize_u32(message.yiaddr, &mut buffer)?;
    serialize_u32(message.siaddr, &mut buffer)?;
    serialize_u32(message.giaddr, &mut buffer)?;
    serialize_u128(message.chaddr, &mut buffer)?;

    buffer.write_all(&message.sname)?;
    buffer.write_all(&message.file)?;

    serialize_options(&message.options, &mut buffer)?;

    while buffer.len() & 0b1111 != 0 {
        serialize_option(&Option::Pad, &mut buffer)?;
    }

    Ok(buffer)
}

fn deserialize_op(caret: &mut Caret<u8>) -> Result<OperationCode> {
    let code = deserialize_u8(caret)?;

    let it = match code {
        1 => OperationCode::BootRequest,
        2 => OperationCode::BootReply,
        it => return ErrorKind::UnsupportedFormat {
            message: format!("Invalid op format > {:?}", it)
        }.into()
    };

    Ok(it)
}

fn deserialize_htype(caret: &mut Caret<u8>) -> Result<Htype> {
    let it = deserialize_u8(caret)?;

    match it {
        1 => Ok(Htype::EthernetMac),
        _ => ErrorKind::UnsupportedFormat {
            message: format!("Unsupported htype > {}", it)
        }.into()
    }
}

fn deserialize_flags(caret: &mut Caret<u8>) -> Result<Flags> {
    let inner = deserialize_u16(caret)?;

    let flags = Flags {
        b: (inner >> 15) != 0,
    };

    Ok(flags)
}

fn deserialize_option(caret: &mut Caret<u8>) -> Result<Option> {
    if !caret.has_next() {
        return ErrorKind::UnsupportedFormat {
            message: format!("Not enught bytes to parse an option")
        }.into()
    }

    let option = match take!(1, caret) {
        0 => Option::Pad,
        1 => {
            deserialize_u8(caret)?;
            Option::SubnetMask {
                mask: deserialize_u32(caret)?
            }
        }
        50 => {
            deserialize_u8(caret)?;
            Option::RequestedIpAddress {
                address: deserialize_u32(caret)?
            }
        }
        51 => {
            deserialize_u8(caret)?;
            Option::IpAddressLeaseTime {
                time: deserialize_u32(caret)?
            }
        }
        53 => {
            deserialize_u8(caret)?;
            Option::DhcpMessageType {
                value: MessageType::from_number(deserialize_u8(caret)?)?
            }
        }
        54 => {
            deserialize_u8(caret)?;
            Option::ServerIdentifier {
                address: deserialize_u32(caret)?
            }
        }
        58 => {
            deserialize_u8(caret)?;
            Option::RenewalTimeValue {
                time: deserialize_u32(caret)?
            }
        }
        59 => {
            deserialize_u8(caret)?;
            Option::RebindingTimeValue {
                time: deserialize_u32(caret)?
            }
        }
        255 => Option::End,
        code => {
            let length = deserialize_u8(caret)? as usize;
            Option::Other {
                code: code,
                data: caret.take(length)?
            }
        }
        // 3 => Option::Router,
        // 6 => Option::DomainNameServer,
        // 33 => Option::StaticRoutingTable,
        // 51 => Option::IpAddressLeaseTime,
        // 53 => Option::DhcpMessageType,
        // 55 => Option::ParameterRequestList,
        // 60 => Option::ClassIdentifier,
        // 61 => Option::ClientIdentifier,
        // 66 => Option::TftpServerName,
        // 67 => Option::BootfileName,
        // 121 => Option::ClasslessStaticRouteOption,
        // 150 => Option::TftpServerAddress,
        // other => Option::Other { code: other },
    };

    Ok(option)
}

fn deserialize_options(caret: &mut Caret<u8>) -> Result<Vec<Option>> {
    if take!(4, caret) != MAGIC_COOKIE {
        return ErrorKind::UnsupportedFormat {
            message: "Magic cookie violation".to_owned()
        }.into()
    }

    let mut options = vec![];
    let mut is_end = false;

    while !is_end && caret.has_next() {
        let option = deserialize_option(caret)?;

        if let Option::End = option {
            is_end = true;
        } else if let Option::Pad = option {
            // Chill
        } else {
            options.push(option);
        }
    }

    Ok(options)
}

pub fn from_bytes(packet: &[u8]) -> Result<Message> {
    let mut caret = Caret { slice: packet };

    let it = Message {
        op: deserialize_op(&mut caret)?,
        htype: deserialize_htype(&mut caret)?,
        hlen: deserialize_u8(&mut caret)?,
        hops: deserialize_u8(&mut caret)?,
        xid: deserialize_u32(&mut caret)?,
        secs: deserialize_u16(&mut caret)?,
        flags: deserialize_flags(&mut caret)?,
        ciaddr: deserialize_u32(&mut caret)?,
        yiaddr: deserialize_u32(&mut caret)?,
        siaddr: deserialize_u32(&mut caret)?,
        giaddr: deserialize_u32(&mut caret)?,
        chaddr: deserialize_u128(&mut caret)?,
        sname: take!(64, caret),
        file: take!(128, caret),
        options: deserialize_options(&mut caret)?,
    };

    Ok(it)
}
