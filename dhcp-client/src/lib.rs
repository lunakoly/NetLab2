pub mod dhcp;

use std::fs::{File};
use std::path::{Path};
use std::io::{Seek, Read, Write};
use std::net::{UdpSocket, SocketAddr};
use std::time::{Duration, Instant};

use rand::{Rng};

use shared::{
    Result,
    ErrorKind,
    with_error_report,
    is_would_block_io_result
};

use shared::shared::{IntoShared, Shared};

pub fn start() {
    let mut rng = rand::thread_rng();
    let xid: u32 = rng.gen();
    
    let discover = dhcp::Message {
        op: dhcp::OperationCode::BootRequest,
        htype: dhcp::Htype::EthernetMac,
        hlen: dhcp::Htype::EthernetMac.hlen(),
        hops: dhcp::CLIENT_HOPS,
        xid: xid,
        secs: 0,
        flags: dhcp::Flags {
            inner: 0,
        },
        
    };

    // with_error_report(run_main_loop);
}
