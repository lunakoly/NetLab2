#![allow(dead_code)]

pub mod shared;

use std::str::{from_utf8, from_utf8_unchecked};

pub fn from_utf8_forced(buffer: &[u8]) -> &str {
    match from_utf8(&buffer) {
        Ok(content) => content,
        Err(error) => unsafe {
            from_utf8_unchecked(&buffer[..error.valid_up_to()])
        }
    }
}
