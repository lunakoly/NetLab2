use std::io::{Write};

use shared::{Result, ErrorKind};

pub const DEFAULT_PORT: u32 = 69;
pub const MAX_DATA_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub enum ErrorCode {
    NotDefined,
    FileNotFound,
    AccessViolation,
    DiskFullOrAllocationExceeded,
    IllegalOperation,
    UnknownTransferId,
    FileAlreadyExists,
    NoSuchUser,
}

pub fn to_error_code_index(error_code: &ErrorCode) -> u16 {
    error_code.clone() as u16
}

#[derive(Debug, Clone)]
pub enum Mode {
    NetAscii,
    Octet,
    Mail,
    Other(String),
}

impl Mode {
    pub fn to_string(&self) -> String {
        match self {
            Mode::NetAscii => "netascii".to_owned(),
            Mode::Octet => "octet".to_owned(),
            Mode::Mail => "mail".to_owned(),
            Mode::Other(it) => it.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Packet {
    Rrq { filename: String, mode: Mode },
    Wrq { filename: String, mode: Mode },
    Data { block: u16, data: Vec<u8> },
    Ack { block: u16 },
    Error { error_code: ErrorCode, error_message: String },
}

pub fn to_opcode(packet: &Packet) -> u16 {
    match packet {
        Packet::Rrq { .. } => 1,
        Packet::Wrq { .. } => 2,
        Packet::Data { .. } => 3,
        Packet::Ack { .. } => 4,
        Packet::Error { .. } => 5,
    }
}

pub fn serialize_opcode<W: Write>(packet: &Packet, mut output: W) -> Result<()> {
    output.write_all(&to_opcode(packet).to_be_bytes())?;
    Ok(())
}

pub fn serialize_string<W: Write>(string: &str, mut output: W) -> Result<()> {
    output.write_all(string.as_bytes())?;
    output.write_all(&[0u8])?;
    Ok(())
}

pub fn serialize_mode<W: Write>(mode: &Mode, output: W) -> Result<()> {
    serialize_string(&mode.to_string(), output)
}

pub fn serialize_error_code<W: Write>(error_code: &ErrorCode, mut output: W) -> Result<()> {
    output.write_all(&to_error_code_index(error_code).to_be_bytes())?;
    Ok(())
}

pub fn to_bytes(packet: &Packet) -> Result<Vec<u8>> {
    let mut buffer = vec![];

    serialize_opcode(packet, &mut buffer)?;

    match packet {
        Packet::Rrq { filename, mode } => {
            serialize_string(filename, &mut buffer)?;
            serialize_mode(mode, &mut buffer)?;
        }
        Packet::Wrq { filename, mode } => {
            serialize_string(filename, &mut buffer)?;
            serialize_mode(mode, &mut buffer)?;
        }
        Packet::Data { block, data } => {
            buffer.write_all(&block.to_be_bytes())?;
            buffer.write_all(data)?;
        }
        Packet::Ack { block } => {
            buffer.write_all(&block.to_be_bytes())?;
        }
        Packet::Error { error_code, error_message } => {
            serialize_error_code(error_code, &mut buffer)?;
            serialize_string(error_message, &mut buffer)?;
        }
    }

    Ok(buffer)
}

struct Caret<'a, T> {
    pub slice: &'a [T],
}

impl<'a, T: Copy> Caret<'a, T> {
    pub fn next(&self) -> T {
        self.slice[0]
    }
}

macro_rules! take {
    ( 1, $caret:expr ) => {
        {
            let first = $caret.slice[0];
            $caret.slice = &$caret.slice[1..];
            first
        }
    };
    ( $count:expr, $caret:expr ) => {
        {
            let mut part = [0u8; $count];

            for it in 0..$count {
                part[it] = $caret.slice[it];
            }

            $caret.slice = &$caret.slice[$count..];
            part
        }
    };
}

fn deserialize_u16(caret: &mut Caret<u8>) -> Result<u16> {
    if caret.slice.len() < 2 {
        return ErrorKind::UnsupportedFormat {
            message: format!("Couldn't deserialize a u16")
        }.into()
    }

    Ok(u16::from_be_bytes(take!(2, caret)))
}

fn deserialize_string(caret: &mut Caret<u8>) -> Result<String> {
    let mut string = String::new();

    while caret.next() != 0 {
        string.push(take!(1, caret) as char);
    }

    take!(1, caret);
    Ok(string)
}

fn deserialize_mode(caret: &mut Caret<u8>) -> Result<Mode> {
    let string = deserialize_string(caret)?.to_lowercase();

    if string == "netascii" {
        Ok(Mode::NetAscii)
    } else if string == "octet" {
        Ok(Mode::Octet)
    } else if string == "mail" {
        Ok(Mode::Mail)
    } else {
        Ok(Mode::Other(string))
    }
}

fn deserialize_error_code(caret: &mut Caret<u8>) -> Result<ErrorCode> {
    let code = deserialize_u16(caret)?;

    let it = match code {
        0 => ErrorCode::NotDefined,
        1 => ErrorCode::FileNotFound,
        2 => ErrorCode::AccessViolation,
        3 => ErrorCode::DiskFullOrAllocationExceeded,
        4 => ErrorCode::IllegalOperation,
        5 => ErrorCode::UnknownTransferId,
        6 => ErrorCode::FileAlreadyExists,
        7 => ErrorCode::NoSuchUser,
        _ => return ErrorKind::UnsupportedFormat {
            message: format!("Invalid error code")
        }.into()
    };

    Ok(it)
}

pub fn from_bytes(packet: &[u8]) -> Result<Packet> {
    let mut caret = Caret { slice: packet };
    let opcode = deserialize_u16(&mut caret)?;

    let packet = match opcode {
        1 => {
            let filename = deserialize_string(&mut caret)?;
            let mode = deserialize_mode(&mut caret)?;
            Packet::Rrq { filename, mode }
        }
        2 => {
            let filename = deserialize_string(&mut caret)?;
            let mode = deserialize_mode(&mut caret)?;
            Packet::Wrq { filename, mode }
        }
        3 => {
            let block = deserialize_u16(&mut caret)?;
            let data = caret.slice.to_vec();
            Packet::Data { block, data }
        }
        4 => {
            let block = deserialize_u16(&mut caret)?;
            Packet::Ack { block }
        }
        5 => {
            let error_code = deserialize_error_code(&mut caret)?;
            let error_message = deserialize_string(&mut caret)?;
            Packet::Error { error_code, error_message }
        }
        _ => return ErrorKind::UnsupportedFormat {
            message: format!("Invalid packet opcode")
        }.into()
    };

    Ok(packet)
}
