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
    inner: u16,
}

impl Flags {
    pub fn b(&self) -> bool {
        (self.inner & (1 << 15)) != 0
    }
}

#[derive(Debug, Clone)]
pub enum MessageType {
    DhcpDiscover,
    DhcpOffer,
    DhcpRequest,
    DhcpAck,
    DhcpNak,
    DhcpDecline,
    DhcpRelease,
    DhcpInform,
}

#[derive(Debug, Clone)]
pub enum Option {
    Pad,
    // SubnetMask { mask: u32 },
    // Router { addresses: Vec<u32> },
    // DomainNameServer { addresses: Vec<u32> },
    // StaticRoutingTable { map: Vec<(u32, u32)> },
    // IpAddressLeaseTime { time: u32 },
    // DhcpMessageType { value: MessageType },
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

pub const DEFAULT_PORT: u32 = 69;

fn serialize_op<W: Write>(op: &OperationCode, output: W) -> Result<()> {
    let id = match op {
        OperationCode::BootRequest => 1,
        OperationCode::BootReply => 2,
    };

    serialize_u8(id, output)
}

fn serialize_htype<W: Write>(value: &Htype, mut output: W) -> Result<()> {
    // See: RFC 1700 «Assigned Numbers»
    serialize_u8(1, output)
}

fn serialize_flags<W: Write>(flags: &Flags, output: W) -> Result<()> {
    serialize_u16(flags.inner, output)
}

fn serialize_option<W: Write>(option: &Option, mut output: W) -> Result<()> {
    match option {
        Option::Pad => {
            serialize_u8(0, output)?;
        }
        Option::End => {
            serialize_u8(255, output)?;
        }
        Option::Other { code, data } => {
            serialize_u8(code.clone(), &mut output)?;
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

    Ok(())
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

    Ok(buffer)
}

fn deserialize_op(caret: &mut Caret<u8>) -> Result<OperationCode> {
    let code = deserialize_u16(caret)?;

    let it = match code {
        1 => OperationCode::BootRequest,
        2 => OperationCode::BootReply,
        _ => return ErrorKind::UnsupportedFormat {
            message: format!("Invalid op format")
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
    let flags = Flags {
        inner: deserialize_u16(caret)?,
    };

    Ok(flags)
}

fn deserialize_options(caret: &mut Caret<u8>) -> Result<Vec<Option>> {
    if take!(4, caret) != MAGIC_COOKIE {
        return ErrorKind::UnsupportedFormat {
            message: "Magic cookie violation".to_owned()
        }.into()
    }
    
    let mut options = vec![];

    while caret.has_next() {
        let option = match take!(1, caret) {
            0 => Option::Pad,
            255 => Option::End,
            code => {
                let length = deserialize_u8(caret)? as usize;
                Option::Other {
                    code: code,
                    data: caret.take(length)?
                }
            },
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

        options.push(option);
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
