use std::env;
use std::net;
use std::str::FromStr;

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
        V4(ip) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            let (mut sender, mut reciever) =
                transport_channel(100, TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy!");

            loop {
                let packet = make_packet_ipv4(ip, ttl);
                sender.send_to(packet, ip_addr);

                let res_packet = reciever.next().expect("Error in recieving next packet! 9S unhappy!");


            }
        },
        V6(ip) => {

        }
}

fn make_packet_ipv4(dest: net::Ipv4Addr, ttl: u8) -> Ipv4Packet {
    let mut ipv4_packet = ipv4::MutableIpv4Packet(&mut [0u8; 100]).unwrap();
    ipv4packet.populate(&ipv4::Ipv4{
        version: 4,
        header_length: 20,
        dscp: 0,
        ecn: 0,
        total_length: 20 + 8 + 64,
        identification: 0,
        flag: 0,
        fragment_offset: 0,
        ttl: ttl,
        next_level_protocol: IpNextHeaderProtocols::Icmp,
        checksum: 0,
        source: Ipv4Addr::from_str("0.0.0.0"),
        destination: dest,
        options: vec![],
        payload: vec![]
    });

    let mut icmp_packet = icmp::echo_request::MutableEchoRequestPacket(&mut [0u8; 8 + 64]).unwrap();
    icmp_packet.populate(&icmp::echo_request::EchoRequest{
        icmp_type: IcmpTypes::EchoRequest,
        icmp_code: icmp::echo_request::IcmpCodes::NoCode,
        checksum: 0,
        identifier: 0,
        sequence_number: 0,
        payload: vec![]
    });

    icmp_packet.set_checksum(icmp::checksum(&icmp_packet));
    ipv4_packet.set_payload(icmp_packet.packet());
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet));

    ipv4_packet.consume_to_immutable()
}

fn make_packet_ipv6(dest: net::Ipv6Addr, hop_limit: u8) -> Ipv6Packet {
    let mut ipv6_packet = ipv4::MutableIpv6Packet(&mut [0u8; 100]).unwrap();
    ipv6packet.populate(&ipv6::Ipv6{
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: 64,
        next_header: IpNextHeaderProtocols::Icmp,
        hop_limit: hop_limit,
        checksum: 0,
        source: Ipv6Addr::from_str("0.0.0.0.0.0"),
        destination: dest,
        payload: vec![]
    });

    let mut icmp_packet = icmpv6::MutableIcmpv6Packet(&mut [0u8; 8 + 64]).unwrap();
    icmp_packet.populate(&icmpv6::Icmpv6{
        icmp_type: Icmpv6Types::EchoRequest,
        icmp_code: icmpv6::ndp::IcmpCodes::NoCode,
        checksum: 0,
        payload: vec![]
    });

    icmp_packet.set_checksum(icmpv6::checksum(&icmp_packet));
    ipv6_packet.set_payload(icmp_packet.packet());
    ipv6_packet.set_checksum(ipv6::checksum(&ipv6_packet));

    ipv6_packet.consume_to_immutable()
}

