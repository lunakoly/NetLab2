use shared::{
    Result,
    ErrorKind,
};

use pnet::datalink::{NetworkInterface};

use pnet::util::{MacAddr};

pub fn get_mac_address(interface: &NetworkInterface) -> Result<MacAddr> {
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

pub fn mac_address_to_bytes(mac_address: MacAddr) -> [u8; 6] {
    [
        mac_address.0,
        mac_address.1,
        mac_address.2,
        mac_address.3,
        mac_address.4,
        mac_address.5,
    ]
}

pub fn mac_address_bytes_to_chaddr(mac_bytes: &[u8; 6]) -> u128 {
    let mut padded_mac = [0u8; 16];

    for it in 0..mac_bytes.len() {
        padded_mac[it] = mac_bytes[it];
    }

    u128::from_be_bytes(padded_mac)
}

pub fn mac_address_to_chaddr(mac_address: MacAddr) -> u128 {
    mac_address_bytes_to_chaddr(&mac_address_to_bytes(mac_address))
}
