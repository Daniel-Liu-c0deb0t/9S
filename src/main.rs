use std::env;
use std::net;
use std::time;
use std::net::ToSocketAddrs;
use std::str::*;

use pnet::packet::*;
use pnet::transport::*;

const DEFAULT_TTL: u8 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_PAYLOAD_SIZE: usize = 56;
const DEFAULT_DELAY_MS: u64 = 1000;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut ttl = DEFAULT_TTL;
    let mut addr = &"".to_string();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    let mut i = 1;
    let mut pos_args = 0;
    let pos_args_max = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                i += 1;
                ttl = args[i].parse::<u8>().expect(format!("{} is not a valid TTL number! 9S unhappy :(", args[i]).as_str());
            },
            "--timeout" => {
                i += 1;
                timeout_ms = args[i].parse::<u64>().expect(format!("{} is not a valid timeout value! 9S unhappy :(", args[i]).as_str());
            },
            _ => {
                if pos_args > pos_args_max {
                    panic!("Too many arguments! 9S unhappy :(");
                }else{
                    addr = &args[i];
                    pos_args += 1;
                }
            }
        }

        i += 1;
    }

    if pos_args != pos_args_max {
        panic!("You are missing an argument! 9S unhappy :(");
    }

    ping(addr, ttl, timeout_ms);
}

pub fn ping(addr: &String, ttl: u8, timeout_ms: u64) {
    let timeout = time::Duration::from_millis(timeout_ms);

    let ip_addr = match net::IpAddr::from_str(addr) {
        Ok(ip) => {
            println!("Pinging {} with 9S's special abilities.", ip);
            ip
        },
        Err(_) => {
            // must be a hostname or an invalid IPv4/IPv6 address
            // workaround to do DNS lookup using SocketAddr; port number does not matter
            let ip = (addr.as_str(), 80u16).to_socket_addrs()
                .expect(format!("{} is not a valid IPv4/IPv6 address or hostname! 9S unhappy!", addr).as_str())
                .next()
                .unwrap()
                .ip();
            println!("Pinging {} ({}) with 9S's special abilities.", addr, ip);
            ip
        }
    };

    let mut total_packets = 0u32;
    let mut lost_packets = 0u32;
    let mut total_rtt = 0u128;
    let identifier = std::process::id() as u16;
    let mut seq_num = 0u16;

    match ip_addr {
        net::IpAddr::V4(_) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            let (mut sender, mut receiver) = transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();
            let mut receiver_iter = icmp_packet_iter(&mut receiver);

            loop {
                total_packets += 1;
                seq_num += 1;
                let mut icmp_buffer = [0u8; 8 + DEFAULT_PAYLOAD_SIZE];
                let packet = make_icmp_packet(&mut icmp_buffer, identifier, seq_num);
                let curr_time = time::Instant::now();

                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy!");

                loop {
                    let res = receiver_iter.next_with_timeout(timeout)
                        .expect("Error in receiving next packet! 9S unhappy!");
                    let res_tuple = match res {
                        Some(p) => p,
                        None => {
                            lost_packets += 1;
                            println!("9S did not received packet from {} in {} ms (timeout); sent {}, with {} ({:.1}%) lost/timeout so far.",
                            addr, timeout_ms, total_packets, lost_packets, lost_packets as f32 / total_packets as f32 * 100.0f32);

                            break;
                        }
                    };

                    match res_tuple.0.get_icmp_type() {
                        icmp::IcmpTypes::EchoReply => {
                            let (res_identifier, res_seq_num) = read_payload(res_tuple.0.payload());

                            if res_identifier == identifier && res_seq_num == seq_num {
                                let elapsed_ms = curr_time.elapsed().as_millis();
                                total_rtt += elapsed_ms;
                                println!("9S received packet from {} in {} ms (avg rtt: {:.1} ms); sent {}, with {} ({:.1}%) lost/timeout so far.",
                                addr, elapsed_ms, total_rtt as f64 / (total_packets - lost_packets) as f64, total_packets, lost_packets, lost_packets as f64 / total_packets as f64 * 100.0f64);

                                break;
                            }
                        },
                        icmp::IcmpTypes::DestinationUnreachable => {
                            lost_packets += 1;
                            println!("{} is unreachable by 9S (code {})! Sent {}, with {} ({:.1}%) lost/timeout so far.",
                            addr, res_tuple.0.get_icmp_code().0, total_packets, lost_packets, lost_packets as f64 / total_packets as f64 * 100.0f64);

                            break;
                        },
                        icmp::IcmpTypes::TimeExceeded => {
                            lost_packets += 1;
                            println!("9S found out that the packet (ttl: {}) expired before reaching {} (last host: {})! Sent {}, with {} ({:.1}%) lost/timeout so far.",
                            ttl, addr, res_tuple.1, total_packets, lost_packets, lost_packets as f64 / total_packets as f64 * 100.0f64);

                            break;
                        },
                        _ => () // keep waiting for the correct packet to come back
                    }
                }

                std::thread::sleep(time::Duration::from_millis(DEFAULT_DELAY_MS));
            }
        },
        net::IpAddr::V6(ip) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            let (mut sender, mut receiver) = transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv6(ip::IpNextHeaderProtocols::Icmpv6)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();
            let mut receiver_iter = icmpv6_packet_iter(&mut receiver);

            loop {
                let mut icmp_buffer = [0u8; 8 + DEFAULT_PAYLOAD_SIZE];
                let packet = make_icmpv6_packet(ip, &mut icmp_buffer, identifier, seq_num);
                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy!");

                loop {
                    let res_packet = receiver_iter.next_with_timeout(timeout)
                        .expect("Error in receiving next packet! 9S unhappy!").unwrap();

                    // we only care about echo replies
                    if res_packet.0.get_icmpv6_type() == icmpv6::Icmpv6Types::EchoReply {
                        println!("{:?}", res_packet);

                        break;
                    }
                }

                std::thread::sleep(time::Duration::from_millis(DEFAULT_DELAY_MS));
            }
        }
    }
}

fn make_icmp_packet(icmp_buffer: &mut [u8], identifier: u16, seq_num: u16) -> icmp::IcmpPacket {
    let mut icmp_packet = icmp::MutableIcmpPacket::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmp::Icmp{
        icmp_type: icmp::IcmpTypes::EchoRequest,
        icmp_code: icmp::IcmpCode::new(0),
        checksum: 0,
        payload: make_payload(identifier, seq_num)
    });

    icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
    icmp_packet.consume_to_immutable()
}

fn make_icmpv6_packet(dest: net::Ipv6Addr, icmp_buffer: &mut [u8], identifier: u16, seq_num: u16) -> icmpv6::Icmpv6Packet {
    let mut icmp_packet = icmpv6::MutableIcmpv6Packet::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmpv6::Icmpv6{
        icmpv6_type: icmpv6::Icmpv6Types::EchoRequest,
        icmpv6_code: icmpv6::Icmpv6Code::new(0),
        checksum: 0,
        payload: make_payload(identifier, seq_num)
    });

    icmp_packet.set_checksum(icmpv6::checksum(
            &icmp_packet.to_immutable(), &net::Ipv6Addr::from_str("0.0.0.0.0.0").unwrap(), &dest));
    icmp_packet.consume_to_immutable()
}

fn make_payload(identifier: u16, seq_num: u16) -> Vec<u8> {
    vec![
        (identifier & ((1 << 8) - 1)) as u8,
        (identifier >> 8) as u8,
        (seq_num & ((1 << 8) - 1)) as u8,
        (seq_num >> 8) as u8
    ]
}

fn read_payload(payload: &[u8]) -> (u16, u16) {
    (payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
     payload[2] as u16 + ((payload[3] as u16) << 8)) // sequence number
}

