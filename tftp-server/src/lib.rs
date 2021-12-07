pub mod tftp;

use std::fs::{File};
use std::path::{Path};
use std::io::{Seek, Read, Write};
use std::net::{UdpSocket, SocketAddr};
use std::time::{Duration, Instant};

use shared::{
    Result,
    ErrorKind,
    with_error_report,
    is_would_block_io_result
};

use shared::shared::{IntoShared, Shared};

#[derive(Debug)]
enum Task {
    Main {
        send_queue: Vec<(tftp::Packet, SocketAddr)>
    },
    Reader {
        send_queue: Vec<tftp::Packet>,
        mode: tftp::Mode,
        tid: SocketAddr,
        file: File,
        size: u64
    },
    Writer {
        send_queue: Vec<tftp::Packet>,
        mode: tftp::Mode,
        tid: SocketAddr,
        file: File
    },
}

impl Task {
    fn has_empty_queue(&self) -> Result<bool> {
        match self {
            Task::Main { send_queue, .. } => Ok(send_queue.len() == 0),
            Task::Reader { send_queue, .. } => Ok(send_queue.len() == 0),
            Task::Writer { send_queue, .. } => Ok(send_queue.len() == 0),
        }
    }

    fn packet_and_tid(&self) -> Result<(tftp::Packet, SocketAddr)> {
        match self {
            Task::Main { send_queue, .. } => {
                Ok(send_queue[0].clone())
            }
            Task::Reader { send_queue, tid, .. } => {
                Ok((send_queue[0].clone(), tid.clone()))
            }
            Task::Writer { send_queue, tid, .. } => {
                Ok((send_queue[0].clone(), tid.clone()))
            },
        }
    }

    fn remove_first_from_queue(&mut self) {
        match self {
            Task::Main { send_queue, .. } => {
                send_queue.remove(0);
            }
            Task::Reader { send_queue, .. } => {
                send_queue.remove(0);
            }
            Task::Writer { send_queue, .. } => {
                send_queue.remove(0);
            },
        }
    }

    fn clear_queue(&mut self) {
        match self {
            Task::Main { send_queue, .. } => {
                send_queue.clear();
            }
            Task::Reader { send_queue, .. } => {
                send_queue.clear();
            }
            Task::Writer { send_queue, .. } => {
                send_queue.clear();
            },
        }
    }
}

#[derive(Debug)]
struct Connection {
    socket: UdpSocket,
    should_close: bool,
    task: Task,
    last_send_time: Instant,
    last_packet: Option<(tftp::Packet, SocketAddr)>,
}

impl Connection {
    fn send_as_main(
        &mut self,
        packet: tftp::Packet,
        address: SocketAddr,
    ) -> Result<()> {
        match &mut self.task {
            Task::Main { send_queue, .. } => {
                send_queue.push((packet, address));
                Ok(())
            }
            _ => ErrorKind::StateViolation {
                message: format!("send_as_main() for non-main")
            }.into()
        }
    }

    fn send_as_non_main(
        &mut self,
        packet: tftp::Packet,
    ) -> Result<()> {
        match &mut self.task {
            Task::Reader { send_queue, .. } => {
                send_queue.push(packet);
                Ok(())
            }
            Task::Writer { send_queue, .. } => {
                send_queue.push(packet);
                Ok(())
            }
            _ => ErrorKind::StateViolation {
                message: format!("send_as_non_main() for main")
            }.into()
        }
    }
}

#[derive(Debug)]
struct Context {
    listener: Shared<Connection>,
    sharers: Vec<Shared<Connection>>,
}

impl Context {
    fn remove_connection(&mut self, connection: Shared<Connection>) -> Result<()> {
        let target_tid = match connection.read()?.task {
            Task::Reader { tid, .. } => tid.clone(),
            Task::Writer { tid, .. } => tid.clone(),
            _ => return Ok(())
        };

        let mut removable: Option<usize> = None;

        for it in 0..self.sharers.len() {
            let that = &self.sharers[it];

            let tid = match that.read()?.task {
                Task::Reader { tid, .. } => tid.clone(),
                Task::Writer { tid, .. } => tid.clone(),
                _ => continue
            };

            if tid == target_tid {
                removable = Some(it);
            }
        }

        if let Some(it) = removable {
            self.sharers.remove(it);
        }

        Ok(())
    }
}

fn file_not_found_packet() -> tftp::Packet {
    tftp::Packet::Error {
        error_code: tftp::ErrorCode::FileNotFound,
        error_message: format!("Nah, never seen nothing like that u know")
    }
}

fn file_exists_packet() -> tftp::Packet {
    tftp::Packet::Error {
        error_code: tftp::ErrorCode::FileAlreadyExists,
        error_message: format!("File is already here")
    }
}

fn illegal_packet() -> tftp::Packet {
    tftp::Packet::Error {
        error_code: tftp::ErrorCode::IllegalOperation,
        error_message: format!("Wait, that's illegal.")
    }
}

fn access_violation_packet() -> tftp::Packet {
    tftp::Packet::Error {
        error_code: tftp::ErrorCode::AccessViolation,
        error_message: format!("Go back and get yourself a permission first.")
    }
}

fn unsupported_mode_packet(mode: &tftp::Mode) -> tftp::Packet {
    tftp::Packet::Error {
        error_code: tftp::ErrorCode::IllegalOperation,
        error_message: format!("Mode '{}' is not supported", mode.to_string())
    }
}

#[allow(dead_code)]
const LINE_FEED: u8 = 10;
#[allow(dead_code)]
const CARRIAGE_RETURN: u8 = 13;

fn read_chunk_as_netascii(file: &mut File, size: u64) -> Result<Vec<u8>> {
    let mut buffer = [0u8; tftp::MAX_DATA_SIZE];
    let mut next_buffer = [0u8; 1];
    let mut index = 0;

    while index < tftp::MAX_DATA_SIZE && file.stream_position()? < size {
        file.read_exact(&mut next_buffer)?;
        let next = next_buffer[0];

        #[cfg(unix)] {
            if next == LINE_FEED {
                buffer[index] = CARRIAGE_RETURN;
                index += 1;
                buffer[index] = LINE_FEED;
                index += 1;
                continue
            }
        }

        #[cfg(windows)] {
            if next == LINE_FEED || next == CARRIAGE_RETURN {
                buffer[index] = next;
                index += 1;
                continue
            }
        }

        if !(0x20..=0x7F).contains(&next) {
            continue
        }

        buffer[index] = next;
        index += 1;
    }

    Ok(buffer[..index].to_vec())
}

fn read_chunk(file: &mut File, size: u64) -> Result<Vec<u8>> {
    let mut buffer = [0u8; tftp::MAX_DATA_SIZE];
    let written = file.stream_position()?;

    let count = if size - written >= tftp::MAX_DATA_SIZE as u64 {
        tftp::MAX_DATA_SIZE
    } else {
        (size - written) as usize
    };

    file.read_exact(&mut buffer[..count])?;
    Ok(buffer[..count].to_vec())
}

fn handle_read_request(
    filename: &str,
    mode: &tftp::Mode,
    address: SocketAddr,
    connection: Shared<Connection>,
    context: &mut Context,
) -> Result<()> {
    if !mode.is_supported() {
        connection.write()?.send_as_main(unsupported_mode_packet(mode), address)?;
        return Ok(())
    }

    if !Path::new(filename).exists() {
        connection.write()?.send_as_main(file_not_found_packet(), address)?;
        return Ok(())
    }

    let mut file = File::open(filename)?;
    let size = file.metadata()?.len();

    let maybe_chunk = match mode {
        tftp::Mode::NetAscii => read_chunk_as_netascii(&mut file, size),
        tftp::Mode::Octet => read_chunk(&mut file, size),
        _ => {
            connection.write()?.send_as_main(unsupported_mode_packet(mode), address)?;
            return Ok(())
        }
    };

    let data = match maybe_chunk {
        Ok(it) => it,
        Err(error) => {
            connection.write()?.send_as_main(file_not_found_packet(), address)?;
            println!("Read Error > {:?} > {}", address, error);
            return Ok(())
        }
    };

    let packet = tftp::Packet::Data { block: 1, data };

    let new_connection = Connection {
        socket: UdpSocket::bind(format!("0.0.0.0:0"))?,
        task: Task::Reader {
            send_queue: vec![packet],
            mode: mode.to_owned(),
            tid: address,
            file: file,
            size: size,
        },
        should_close: false,
        last_send_time: Instant::now(),
        last_packet: None,
    };

    new_connection.socket.set_nonblocking(true)?;
    context.sharers.push(new_connection.to_shared());

    Ok(())
}

fn handle_write_request(
    filename: &str,
    mode: &tftp::Mode,
    address: SocketAddr,
    connection: Shared<Connection>,
    context: &mut Context,
) -> Result<()> {
    if !mode.is_supported() {
        connection.write()?.send_as_main(unsupported_mode_packet(mode), address)?;
        return Ok(())
    }

    if Path::new(filename).exists() {
        connection.write()?.send_as_main(file_exists_packet(), address)?;
        return Ok(())
    }

    let file = match File::create(filename) {
        Ok(it) => it,
        Err(error) => {
            connection.write()?.send_as_main(access_violation_packet(), address)?;
            println!("Write Error > {:?} > {}", address, error);
            return Ok(())
        }
    };

    let packet = tftp::Packet::Ack { block: 0 };

    let new_connection = Connection {
        socket: UdpSocket::bind(format!("0.0.0.0:0"))?,
        task: Task::Writer {
            send_queue: vec![packet],
            mode: mode.to_owned(),
            tid: address,
            file: file,
        },
        should_close: false,
        last_send_time: Instant::now(),
        last_packet: None,
    };

    new_connection.socket.set_nonblocking(true)?;
    context.sharers.push(new_connection.to_shared());
    Ok(())
}

fn write_as_netascii(
    file: &mut File,
    buffer: &[u8],
) -> std::io::Result<()> {
    for it in buffer {
        #[cfg(unix)] {
            if it == &CARRIAGE_RETURN {
                continue
            }
        }

        file.write(&[it.clone()])?;
    }

    Ok(())
}

fn handle_data(
    block: u16,
    data: &Vec<u8>,
    connection: Shared<Connection>,
) -> Result<()> {
    let mut locked = connection.write()?;
    let last_packet = locked.last_packet.clone();

    let maybe_info = match &mut locked.task {
        Task::Writer { file, tid, mode, .. } => Some((file, tid, mode)),
        _ => None,
    };

    let (file, tid, mode) = if let Some((file, tid, mode)) = maybe_info {
        (file, tid.clone(), mode.clone())
    } else {
        locked.send_as_non_main(illegal_packet())?;
        return Ok(())
    };

    if let Some((it, ..)) = last_packet {
        let last_block = match it {
            tftp::Packet::Ack { block, .. } => Some(block),
            _ => None,
        };

        if let Some(that) = last_block {
            if block <= that {
                locked.send_as_main(illegal_packet(), tid.clone())?;
                return Ok(())
            }
        }
    }

    let result = match mode {
        tftp::Mode::NetAscii => write_as_netascii(file, data),
        tftp::Mode::Octet => file.write_all(&data),
        _ => {
            connection.write()?.send_as_main(unsupported_mode_packet(&mode), tid)?;
            return Ok(())
        }
    };

    if let Err(error) = result {
        locked.send_as_main(access_violation_packet(), tid.clone())?;
        println!("Write Error > {:?} > {}", tid, error);
        return Ok(())
    }

    let ack = tftp::Packet::Ack {
        block: block,
    };

    locked.send_as_non_main(ack)?;

    if data.len() < tftp::MAX_DATA_SIZE {
        locked.should_close = true;
    }

    Ok(())
}

fn handle_ack(
    block: u16,
    connection: Shared<Connection>,
) -> Result<()> {
    let mut locked = connection.write()?;
    let last_packet = locked.last_packet.clone();

    let maybe_info = match &mut locked.task {
        Task::Reader { file, size, .. } => Some((file, size.clone())),
        _ => None,
    };

    let (mut file, size) = if let Some(it) = maybe_info {
        it
    } else {
        locked.send_as_non_main(illegal_packet())?;
        return Ok(())
    };

    if let Some((it, ..)) = last_packet {
        let last_block = match it {
            tftp::Packet::Data { block, .. } => Some(block),
            _ => None,
        };

        if let Some(that) = last_block {
            if block < that {
                return Ok(())
            }
        }
    }

    if file.stream_position()? < size {
        let data = read_chunk(&mut file, size)?;
        let packet = tftp::Packet::Data { block: block + 1, data };

        locked.send_as_non_main(packet)?;
    } else {
        locked.should_close = true;
    }

    Ok(())
}

fn drop_connection(
    connection: Shared<Connection>,
) -> Result<()> {
    connection.write()?.should_close = true;
    connection.write()?.task.clear_queue();
    Ok(())
}

fn handle_error(
    error_code: tftp::ErrorCode,
    error_message: &str,
    address: SocketAddr,
    connection: Shared<Connection>,
) -> Result<()> {
    println!("Error > {} > {:?} > {}", &address, &error_code, error_message);
    drop_connection(connection)
}

fn handle_datagram(
    packet: tftp::Packet,
    address: SocketAddr,
    connection: Shared<Connection>,
    context: &mut Context,
) -> Result<()> {
    println!("==> {:?}\n", &packet);

    match &packet {
        tftp::Packet::Rrq { filename, mode } => {
            handle_read_request(filename, mode, address, connection, context)
        }
        tftp::Packet::Wrq { filename, mode } => {
            handle_write_request(filename, mode, address, connection, context)
        }
        tftp::Packet::Data { block, data } => {
            handle_data(block.clone(), data, connection)
        }
        tftp::Packet::Ack { block } => {
            handle_ack(block.clone(), connection)
        }
        tftp::Packet::Error { error_code, error_message } => {
            handle_error(error_code.clone(), error_message, address, connection)
        }
    }
}

fn handle_incomming(
    connection: Shared<Connection>,
    context: &mut Context,
) -> Result<bool> {
    let mut buffer = [0u8; MAX_SIZE];

    let result = connection.write()?.socket.recv_from(&mut buffer);

    if is_would_block_io_result(&result) {
        return Ok(false);
    }

    let (size, address) = result?;
    let maybe_bytes = tftp::from_bytes(&buffer[..size]);

    match maybe_bytes {
        Ok(packet) => {
            handle_datagram(packet, address, connection, context)?;
        }
        Err(error) => {
            connection.write()?.send_as_main(illegal_packet(), address)?;
            println!("Error > {} > {}", &address, error);
            drop_connection(connection)?;
        }
    }

    Ok(true)
}

fn send_packet(
    packet: tftp::Packet,
    address: SocketAddr,
    connection: Shared<Connection>,
) -> Result<bool> {
    let bytes = tftp::to_bytes(&packet)?;
    let result = connection.write()?.socket.send_to(&bytes, address);

    if is_would_block_io_result(&result) {
        return Ok(false);
    }

    let sent = result?;

    if sent != bytes.len() {
        return ErrorKind::UnsupportedFormat {
            message: format!("send_to() sent only {} bytes for a {} bytes packet", sent, bytes.len())
        }.into()
    }

    println!("<== {:?}\n", &packet);
    connection.write()?.task.remove_first_from_queue();

    if let tftp::Packet::Error { .. } = packet {
        let should_drop = match connection.read()?.task {
            Task::Reader { .. } => true,
            Task::Writer { .. } => true,
            _ => false,
        };

        if should_drop {
            drop_connection(connection)?;
        }
    } else {
        connection.write()?.last_packet = Some((packet.clone(), address));
        connection.write()?.last_send_time = Instant::now();
    }

    Ok(true)

}

const RESEND_TIME_SEC: u64 = 1;

fn handle_outcomming(
    connection: Shared<Connection>,
) -> Result<bool> {
    if let Some((packet, tid)) = connection.read()?.last_packet.clone() {
        if connection.read()?.last_send_time.elapsed().as_secs() > RESEND_TIME_SEC {
            return send_packet(packet, tid, connection.clone());
        }
    }

    if connection.write()?.task.has_empty_queue()? {
        return Ok(false);
    }

    let (packet, address) = connection.write()?.task.packet_and_tid()?;

    send_packet(packet, address, connection)
}

fn handle_connection(
    connection: Shared<Connection>,
    context: &mut Context,
) -> Result<bool> {
    let mut did_something = false;

    did_something |= handle_incomming(connection.clone(), context)?;
    did_something |= handle_outcomming(connection.clone())?;

    if !did_something && connection.read()?.should_close {
        context.remove_connection(connection.clone())?;
    }

    Ok(did_something)
}

const MAX_SIZE: usize = 2048;
const WAITING_DELAY_MILLIS: u64 = 16;

fn create_listener() -> Result<Shared<Connection>> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", tftp::DEFAULT_PORT))?;
    socket.set_nonblocking(true)?;

    let connection = Connection {
        socket: socket,
        task: Task::Main {
            send_queue: vec![],
        },
        should_close: false,
        last_send_time: Instant::now(),
        last_packet: None,
    };

    Ok(connection.to_shared())
}

fn run_main_loop() -> Result<()> {
    let mut context = Context {
        listener: create_listener()?,
        sharers: vec![],
    };

    loop {
        let mut did_something = false;

        did_something |= handle_connection(context.listener.clone(), &mut context)?;

        let sharers = context.sharers.clone();

        for it in sharers {
            did_something |= handle_connection(it.clone(), &mut context)?;
        }

        if !did_something {
            std::thread::sleep(Duration::from_millis(WAITING_DELAY_MILLIS));
        }
    }
}

pub fn start() {
    with_error_report(run_main_loop);
}
