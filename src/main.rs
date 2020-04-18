use std;
use std::mem;
use std::collections;
use std::thread;
use std::env;
use std::sync;
use std::sync::atomic;
use std::net;
use std::time;
use std::net::ToSocketAddrs;
use std::str::*;

use pnet::packet::*;
use pnet::transport::*;

use ctrlc;

const DEFAULT_TTL: u8 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_PAYLOAD_SIZE: usize = 56;
const DEFAULT_DELAY_MS: u64 = 1000;
const DEFAULT_ITER: usize = usize::max_value();

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut ttl = DEFAULT_TTL;
    let mut addr = &"".to_string();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut delay_ms = DEFAULT_DELAY_MS;
    let mut iterations = DEFAULT_ITER;

    let mut i = 1;
    let mut pos_args = 0;
    let pos_args_max = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                i += 1;
                ttl = args[i].parse::<u8>().expect(format!("{} is not a valid TTL value! 9S unhappy :(", args[i]).as_str());
            },
            "--timeout" => {
                i += 1;
                timeout_ms = args[i].parse::<u64>().expect(format!("{} is not a valid timeout value in ms! 9S unhappy :(", args[i]).as_str());
            },
            "--delay" => {
                i += 1;
                delay_ms = args[i].parse::<u64>().expect(format!("{} is not a valid delay value in ms! 9S unhappy :(", args[i]).as_str());
            },
            "--iter" => {
                i += 1;
                iterations = args[i].parse::<usize>().expect(format!("{} is not a valid number of iterations! 9S unhappy :(", args[i]).as_str());
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

    ping(addr, iterations, ttl, timeout_ms, delay_ms);
}

pub fn ping(addr: &String, iterations: usize, ttl: u8, timeout_ms: u64, delay_ms: u64) {
    let timeout = time::Duration::from_millis(timeout_ms);
    let delay = time::Duration::from_millis(delay_ms);

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

    let identifier = std::process::id() as u16;

    match ip_addr {
        net::IpAddr::V4(_) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            // it will take care of wrapping our ICMP packets with IPv4/IPv6 packets before sending
            let (mut sender, receiver) = transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();

            let not_done = sync::Arc::new(atomic::AtomicBool::new(true));
            let total_packets = sync::Arc::new(atomic::AtomicUsize::new(0));

            make_exit_handler(not_done.clone());

            let receiver_thread = make_icmp_receiver_thread(not_done.clone(), receiver, total_packets.clone(), identifier, timeout, addr.clone());

            while not_done.load(atomic::Ordering::SeqCst) &&
                total_packets.load(atomic::Ordering::SeqCst) < iterations {
                total_packets.fetch_add(1, atomic::Ordering::SeqCst);

                let mut icmp_buffer = [0u8; 8 + DEFAULT_PAYLOAD_SIZE];
                let packet = make_icmp_packet(&mut icmp_buffer, identifier, total_packets.load(atomic::Ordering::SeqCst) as u16);

                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy :(");

                thread::sleep(delay);
            }

            if not_done.load(atomic::Ordering::SeqCst) {
                not_done.store(false, atomic::Ordering::SeqCst);

                match timeout.checked_sub(delay) {
                    Some(time) => thread::sleep(time),
                    None => ()
                }
            }

            let (received, lost) = receiver_thread.join().unwrap();
            let total = total_packets.load(atomic::Ordering::SeqCst);
            let timedout = if lost + received > total {0} else {total - received - lost};
            println!("\nDone! 9S sent {} packets total to {}.\n\t9S received {} ({:.1}%) received, lost {} ({:.1}%), and realized that {} ({:.1}%) timed out.",
                total, addr, received, received as f64 / total as f64 * 100f64, lost, lost as f64 / total as f64 * 100f64, timedout, timedout as f64 / total as f64 * 100f64);
        },
        net::IpAddr::V6(ip) => {

        }
    }
}

fn make_icmp_receiver_thread(not_done: sync::Arc<atomic::AtomicBool>,
                             mut receiver: TransportReceiver,
                             total_packets: sync::Arc<atomic::AtomicUsize>,
                             identifier: u16,
                             timeout: time::Duration,
                             addr: String) -> thread::JoinHandle<(usize, usize)> {
    thread::spawn(move || {
        let mut receiver_iter = icmp_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;
        let mut received = collections::HashSet::new();

        while not_done.load(atomic::Ordering::SeqCst) {
            let next_res = receiver_iter.next_with_timeout(time::Duration::from_millis(300))
                .expect("Error receiving packet! 9S unhappy :(");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue
            };

            let total_packets_sent = total_packets.load(atomic::Ordering::SeqCst);

            match res_packet.get_icmp_type() {
                icmp::IcmpTypes::EchoReply => {
                    let (res_identifier, res_seq_num, res_send_time) = read_payload(res_packet.payload());

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet from {}!", addr);
                        }else{
                            let elapsed_ms = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis() - res_send_time;
                            total_rtt += elapsed_ms;

                            if elapsed_ms > timeout.as_millis() {
                                println!("9S received timed out packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }else{
                                received_packets += 1;
                                println!("9S received packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                    res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }

                            received.insert(res_seq_num);
                        }
                    }
                    // quietly skip this received packet if it is not sent by this process
                },
                icmp::IcmpTypes::DestinationUnreachable => {
                    lost_packets += 1;
                    println!("9S received a destination unreachable packet from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                        addr, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                },
                icmp::IcmpTypes::TimeExceeded => {
                    lost_packets += 1;
                    println!("9S received a time exceeded packet before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                        addr, res_ip, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                },
                _ => () // quietly skip this received packet if it is not what we were expecting
            }
        }

        (received_packets, lost_packets)
    })
}

fn make_exit_handler(not_done: sync::Arc<atomic::AtomicBool>) {
    ctrlc::set_handler(move || not_done.store(false, atomic::Ordering::SeqCst)).unwrap();
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
    let curr_time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis();
    let arr = unsafe {mem::transmute::<u128, [u8; 16]>(curr_time)};

    let mut res = vec![
        (identifier & ((1 << 8) - 1)) as u8,
        (identifier >> 8) as u8,
        (seq_num & ((1 << 8) - 1)) as u8,
        (seq_num >> 8) as u8
    ];

    res.extend_from_slice(&arr);
    res
}

fn read_payload(payload: &[u8]) -> (u16, u16, u128) {
    let sent_time = unsafe {
        let num = 0u128;
        let mut arr = mem::transmute::<u128, [u8; 16]>(num);
        arr.copy_from_slice(&payload[4..20]);
        mem::transmute::<[u8; 16], u128>(arr)
    };

    (payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
     payload[2] as u16 + ((payload[3] as u16) << 8), // sequence number
     sent_time)
}

