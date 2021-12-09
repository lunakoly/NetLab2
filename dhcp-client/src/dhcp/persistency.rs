enum Identity {
    HardwareAddress([u8; 6]),
    HostName(String),
}

struct Key {
    ip_subnet_number: String,
    identity: Identity,
}
