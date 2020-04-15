use std::env;
use std::net;
use std::str::*;

use pnet::packet::*;
use pnet::transport::*;

const PAYLOAD_SIZE: usize = 56;
const DELAY_MILLIS: u64 = 500;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut ttl = u8::max_value();
    let mut addr = &"".to_string();

    let mut i = 1;
    let mut pos_args = 0;
    let pos_args_max = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                i += 1;
                ttl = args[i].parse::<u8>().expect(format!("{} is not a valid TTL number! 9S unhappy :(", args[i]).as_str());
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

    let ip_addr = net::IpAddr::from_str(addr)
        .expect(format!("{} is not a valid IPv4/IPv6 address or hostname! 9S unhappy!", addr).as_str());

    println!("Pinging {} ({}) with 9S's special abilities.", addr, ip_addr);

    match ip_addr {
        net::IpAddr::V4(_) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            let (mut sender, mut receiver) = transport_channel(100, TransportChannelType::Layer4(
                    TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();
            let mut receiver_iter = icmp_packet_iter(&mut receiver);

            loop {
                let mut icmp_buffer = [0u8; 8 + PAYLOAD_SIZE];
                let packet = make_icmp_packet(&mut icmp_buffer);
                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy!");

                loop {
                    let res_packet = receiver_iter.next().expect("Error in receiving next packet! 9S unhappy!");

                    if res_packet.0.get_icmp_type() == icmp::IcmpTypes::EchoReply {
                        println!("{:?}", res_packet);

                        break;
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(DELAY_MILLIS));
            }
        },
        net::IpAddr::V6(ip) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            let (mut sender, mut receiver) = transport_channel(100, TransportChannelType::Layer4(
                    TransportProtocol::Ipv6(ip::IpNextHeaderProtocols::Icmpv6)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();
            let mut receiver_iter = icmpv6_packet_iter(&mut receiver);

            loop {
                let mut icmp_buffer = [0u8; 8 + PAYLOAD_SIZE];
                let packet = make_icmpv6_packet(ip, &mut icmp_buffer);
                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy!");

                loop {
                    let res_packet = receiver_iter.next().expect("Error in receiving next packet! 9S unhappy!");

                    if res_packet.0.get_icmpv6_type() == icmpv6::Icmpv6Types::EchoReply {
                        println!("{:?}", res_packet);

                        break;
                    }
                }
            }
        }
    }
}

fn make_icmp_packet(icmp_buffer: &mut [u8]) -> icmp::IcmpPacket {
    let mut icmp_packet = icmp::MutableIcmpPacket::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmp::Icmp{
        icmp_type: icmp::IcmpTypes::EchoRequest,
        icmp_code: icmp::IcmpCode::new(0),
        checksum: 0,
        payload: vec![]
    });

    icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
    icmp_packet.consume_to_immutable()
}

fn make_icmpv6_packet(dest: net::Ipv6Addr, icmp_buffer: &mut [u8]) -> icmpv6::Icmpv6Packet {
    let mut icmp_packet = icmpv6::MutableIcmpv6Packet::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmpv6::Icmpv6{
        icmpv6_type: icmpv6::Icmpv6Types::EchoRequest,
        icmpv6_code: icmpv6::ndp::Icmpv6Codes::NoCode,
        checksum: 0,
        payload: vec![]
    });

    icmp_packet.set_checksum(icmpv6::checksum(
            &icmp_packet.to_immutable(), &net::Ipv6Addr::from_str("0.0.0.0.0.0").unwrap(), &dest));
    icmp_packet.consume_to_immutable()
}

