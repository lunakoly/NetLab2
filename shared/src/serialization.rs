use std::io::{Write};

use crate::{Result, ErrorKind};
use crate::helpers::caret::{Caret};

use crate::{take};

pub fn serialize_string<W: Write>(string: &str, mut output: W) -> Result<()> {
    output.write_all(string.as_bytes())?;
    output.write_all(&[0u8])?;
    Ok(())
}

pub fn deserialize_string(caret: &mut Caret<u8>) -> Result<String> {
    let mut string = String::new();

    while caret.next() != 0 {
        string.push(take!(1, caret) as char);
    }

    take!(1, caret);
    Ok(string)
}

pub fn serialize_u8<W: Write>(number: u8, mut output: W) -> Result<()> {
    output.write_all(&number.to_be_bytes())?;
    Ok(())
}

pub fn deserialize_u8(caret: &mut Caret<u8>) -> Result<u8> {
    if caret.slice.len() < 1 {
        return ErrorKind::UnsupportedFormat {
            message: format!("Couldn't deserialize a u8")
        }.into()
    }

    Ok(take!(1, caret))
}

pub fn serialize_u16<W: Write>(number: u16, mut output: W) -> Result<()> {
    output.write_all(&number.to_be_bytes())?;
    Ok(())
}

pub fn deserialize_u16(caret: &mut Caret<u8>) -> Result<u16> {
    if caret.slice.len() < 2 {
        return ErrorKind::UnsupportedFormat {
            message: format!("Couldn't deserialize a u16")
        }.into()
    }

    Ok(u16::from_be_bytes(take!(2, caret)))
}

pub fn serialize_u32<W: Write>(number: u32, mut output: W) -> Result<()> {
    output.write_all(&number.to_be_bytes())?;
    Ok(())
}

pub fn deserialize_u32(caret: &mut Caret<u8>) -> Result<u32> {
    if caret.slice.len() < 4 {
        return ErrorKind::UnsupportedFormat {
            message: format!("Couldn't deserialize a u32")
        }.into()
    }

    Ok(u32::from_be_bytes(take!(4, caret)))
}

pub fn serialize_u128<W: Write>(number: u128, mut output: W) -> Result<()> {
    output.write_all(&number.to_be_bytes())?;
    Ok(())
}

pub fn deserialize_u128(caret: &mut Caret<u8>) -> Result<u128> {
    if caret.slice.len() < 16 {
        return ErrorKind::UnsupportedFormat {
            message: format!("Couldn't deserialize a u128")
        }.into()
    }

    Ok(u128::from_be_bytes(take!(16, caret)))
}
