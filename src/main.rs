use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr, SocketAddr}};
use byteorder::{ByteOrder, NetworkEndian};
use std::time::{Duration, Instant};
fn checksum(data : &[u8]) -> u16 {
    let mut sum = 0u32;

    let mut i = 0;

    while i < data.len() - 1{
        let word = NetworkEndian::read_u16(&data[i..]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum = sum.wrapping_add(u32::from(data[i] << 8));
    }
    while (sum >> 16) != 0 {
        // this function handles carry over (ensuring the value stays within 16 bits even if the number exceeds the capacity)
        sum = (sum & 0xFFFF) + (sum >> 16); // folds the carry ( sum >> 16) back onto the lower 16 bits of sum
    }

    !sum as u16
}
fn main() {

    let icmp_type : u8 = 14;
    let icmp_code : u8 = 0;
    let identifier : u16 = 6942;
    let sequence_number : u16 = 1;
    let target_ip = "192.168.1.100"; 
    let target_port = 8080; 
    let target_address = format!("{}:{}", target_ip, target_port);

    let target_socket_addr: SocketAddr = target_address.parse().expect("Invalid target address");

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::ICMPV4)).unwrap();

    let ttl: u32 = 1;

    let payload = b"custom packet";

    let mut packet =         vec![0u8 ; 8 + payload.len()];
    packet[0] = icmp_type;
    packet[1] = icmp_code; 
    // packet[2..4] = // TODO;
    NetworkEndian::write_u16(&mut packet[4..6], identifier);
    NetworkEndian::write_u16(&mut packet[6..8], sequence_number);
    packet[8..].copy_from_slice(payload);

    let checksum_value = checksum(&packet);
    NetworkEndian::write_u16(&mut packet[2..4], checksum_value);
    let target_sockaddr = SockAddr::from(target_socket_addr);

    socket.set_read_timeout(Some(Duration::from_secs(5)));

    socket.send_to(&packet, &target_sockaddr).unwrap();

    // Create a buffer that can hold 4 bytes (since a u32 is 4 bytes)
    let mut buf: [MaybeUninit<u8>; 4] = MaybeUninit::uninit_array(); // Array of 4 uninitialized bytes

    // Convert this uninitialized buffer into a mutable slice of bytes
    let buf_bytes: &mut [MaybeUninit<u8>] = &mut buf;
    

    match socket.recv_from(buf_bytes) {
        Ok((size, sockaddr)) => {
            println!("Received {} bytes from {:?}", size, sockaddr);

            // SAFETY: We assume `recv_from` has initialized the buffer correctly
            let initialized_buf: [u8; 4] = unsafe { std::mem::transmute(buf) };

            let value: u32 = u32::from_be_bytes(initialized_buf);  // From big-endian bytes to u32
            println!("Received u32: {}", value);
        },
        Err(err) => {
            println!("No response: {}", err);
        }
    }
}
    println!("Hello, world!");


