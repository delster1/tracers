use socket2::{Domain, Protocol, Socket, SockAddr, Type};
use std::{mem::{uninitialized, MaybeUninit}, net::{Ipv4Addr, SocketAddrV4}};
use byteorder::{ByteOrder, NetworkEndian};
use std::time::{Duration, Instant};

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < data.len() {
        let word = if i == data.len() - 1 {
            u16::from(data[i]) << 8
        } else {
            NetworkEndian::read_u16(&data[i..i + 2])
        };
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identifier = 6942;
    let target_ip: Ipv4Addr = "8.8.8.8".parse()?;
    let target_addr = SocketAddrV4::new(target_ip, 0);
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    
    let max_hops = 30;
    let timeout = Duration::from_secs(1);

    for ttl in 1..=max_hops {
        socket.set_ttl(ttl)?;
        let mut sequence_number = ttl as u16;
        let mut received = false;

        // Send 3 probes per TTL
        for _ in 0..3 {
            let mut packet = vec![8u8, 0, 0, 0,0,0,0, 0, 0]; // ICMP type 8 (echo request), code 0
            NetworkEndian::write_u16(&mut packet[4..6], identifier);
            NetworkEndian::write_u16(&mut packet[6..8], sequence_number);
            packet.extend_from_slice(b"custom packet");
            
            let checksum = checksum(&packet);
            NetworkEndian::write_u16(&mut packet[2..4], checksum);
            
            let send_time = Instant::now();
            socket.send_to(&packet, &SockAddr::from(target_addr))?;

            // Receive response
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let start_time = Instant::now();
            loop {
                if start_time.elapsed() > timeout {
                    print!(" *");
                    break;
                }

                match socket.recv_from(&mut buf) {
                    Ok((size, _)) => {
                        let data = unsafe {
                            std::slice::from_raw_parts(buf.as_ptr() as *const u8, size)
                        };
                        
                        // Parse IP header
                        let ip_header_len = ((data[0] & 0x0F) as usize) * 4;
                        if data.len() < ip_header_len + 8 {
                            continue;
                        }

                        let icmp_type = data[ip_header_len];
                        let icmp_code = data[ip_header_len + 1];

                        match icmp_type {
                            // Time Exceeded
                            11 => {
                                let source_ip = Ipv4Addr::new(
                                    data[12], data[13], data[14], data[15]
                                );
                                let rtt = send_time.elapsed().as_millis();
                                print!(" {}ms", rtt);
                                received = true;
                                break;
                            }
                            // Echo Reply
                            0 => {
                                let received_id = NetworkEndian::read_u16(&data[ip_header_len + 4..]);
                                let received_seq = NetworkEndian::read_u16(&data[ip_header_len + 6..]);
                                
                                if received_id == identifier && received_seq == sequence_number {
                                    let source_ip = Ipv4Addr::new(
                                        data[12], data[13], data[14], data[15]
                                    );
                                    println!("\nReached target {} in {}ms", source_ip, send_time.elapsed().as_millis());
                                    return Ok(());
                                }
                            }
                            _ => continue,
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        print!(" *");
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            sequence_number += 1;
        }

        if received {
            println!();
        } else {
            println!("  No response");
        }

        if ttl == max_hops {
            println!("Maximum hops reached");
            break;
        }
    }

    Ok(())
}
