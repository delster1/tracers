use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4}};
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
        sum = sum.wrapping_add((u32::from(data[i])) << 8);
    }
    while (sum >> 16) != 0 {
        // this function handles carry over (ensuring the value stays within 16 bits even if the number exceeds the capacity)
        sum = (sum & 0xFFFF) + (sum >> 16); // folds the carry ( sum >> 16) back onto the lower 16 bits of sum
    }

    !sum as u16
}
fn main() {

    let icmp_type : u8 = 0;
    let icmp_code : u8 = 0;
    let identifier : u16 = 6942;
    let sequence_number : u16 = 1;

    // Define the target IP as a string
    let target_ip_str = "0.0.0.0";

    // Parse the IP address separately
    let target_ip: Ipv4Addr = target_ip_str.parse().expect("Invalid IP address");

    // Define the target socket address with port 0 (ports are not used for ICMP)
    let target_socket_addr = SocketAddrV4::new(target_ip, 1);


    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::ICMPV4) ).unwrap();

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

    socket.send_to(&packet, &target_sockaddr).expect("Failed to send ICMP Packet");

    let mut buf: [MaybeUninit<u8>; 4] = unsafe { MaybeUninit::uninit().assume_init() };

    // Convert this uninitialized buffer into a mutable slice of bytes
    let buf_bytes: &mut [MaybeUninit<u8>] = &mut buf;
    

    match socket.recv_from(unsafe { &mut *(buf_bytes as *mut _ as *mut [MaybeUninit<u8>]) }) {
        Ok((size, sockaddr)) => {
            // Handle the received data here
            println!("Received {} bytes from {:?}", size, sockaddr);

            // SAFETY: We assume `recv_from` has initialized the buffer correctly
            let initialized_buf: [u8; 4] = unsafe { std::mem::transmute(buf) };

            // If you want to interpret the bytes as a `u32`
            let value: u32 = u32::from_be_bytes(initialized_buf);  // From big-endian bytes to u32
            println!("Received u32: {}", value);
        }
        Err(err) => {
            println!("Error receiving data: {}", err);
        }
    }
}


