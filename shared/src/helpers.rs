#![allow(dead_code)]

pub mod shared;
pub mod caret;

use std::str::{from_utf8, from_utf8_unchecked};

use crate::{Result, ErrorKind};

pub fn from_utf8_forced(buffer: &[u8]) -> &str {
    match from_utf8(&buffer) {
        Ok(content) => content,
        Err(error) => unsafe {
            from_utf8_unchecked(&buffer[..error.valid_up_to()])
        }
    }
}

pub fn misconfiguration<T>(message: &str) -> Result<T> {
    ErrorKind::Configuration {
        message: "Error > ".to_owned() + message
    }.into()
}

pub fn report<T: Default>(message: &str) -> Result<T> {
    println!("Warning > {}", message);
    Ok(T::default())
}

pub fn warning<T: Default>(message: &str) -> Result<T> {
    let it = "Warning > {}".to_owned() + message;
    report(&it)
}
