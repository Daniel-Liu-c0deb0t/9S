use std;
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
            let (mut sender, receiver) = transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy!");
            sender.set_ttl(ttl).unwrap();

            let sent_packets = sync::Arc::new(sync::Mutex::new(Vec::with_capacity(20)));
            let not_done = sync::Arc::new(atomic::AtomicBool::new(true));

            let receiver_thread = make_icmp_receiver_thread(not_done.clone(), receiver, sent_packets.clone(), identifier, addr.clone());
            let timeout_thread = make_icmp_timeout_thread(not_done.clone(), sent_packets.clone(), timeout, addr.clone());

            for _ in 0..iterations {
                let mut icmp_buffer = [0u8; 8 + DEFAULT_PAYLOAD_SIZE];
                let curr_time = time::Instant::now();

                let packet = {
                    let mut sent_packets_locked = sent_packets.lock().unwrap();
                    let p = make_icmp_packet(&mut icmp_buffer, identifier, sent_packets_locked.len() as u16 + 1);
                    sent_packets_locked.push(Some(time::Instant::now()));
                    p
                };

                sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy!");

                // ensure that we send a packet exactly once every delay_ms milliseconds
                match time::Duration::from_millis(delay_ms).checked_sub(curr_time.elapsed()) {
                    Some(time) => thread::sleep(time),
                    None => ()
                }
            }

            not_done.store(false, atomic::Ordering::SeqCst);

            receiver_thread.join().unwrap();
            timeout_thread.join().unwrap();
        },
        net::IpAddr::V6(ip) => {

        }
    }
}

fn make_icmp_receiver_thread(not_done: sync::Arc<atomic::AtomicBool>,
                             mut receiver: TransportReceiver,
                             sent_packets: sync::Arc<sync::Mutex<Vec<Option<time::Instant>>>>,
                             identifier: u16, addr: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut receiver_iter = icmp_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;

        while not_done.load(atomic::Ordering::SeqCst) {
            let next_res = receiver_iter.next_with_timeout(time::Duration::from_millis(1000))
                .expect("Error receiving packet! 9S unhappy :(");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue
            };

            match res_packet.get_icmp_type() {
                icmp::IcmpTypes::EchoReply => {
                    let (res_identifier, res_seq_num) = read_payload(res_packet.payload());
                    let mut sent_packets_locked = sent_packets.lock().unwrap();

                    if res_identifier == identifier && (res_seq_num as usize) <= sent_packets_locked.len() {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        match sent_packets_locked[res_seq_num as usize - 1] {
                            Some(send_time) => {
                                let elapsed_ms = send_time.elapsed().as_millis();
                                total_rtt += elapsed_ms;
                                received_packets += 1;
                                println!("9S received packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, sent_packets_locked.len(), lost_packets, lost_packets as f64 / sent_packets_locked.len() as f64 * 100f64);
                                sent_packets_locked[res_seq_num as usize - 1] = None;
                            },
                            None => {
                                println!("9S received a duplicate packet from {}!", addr);
                            }
                        }

                        break;
                    }
                    // quietly skip this received packet if it is not sent by this process
                },
                icmp::IcmpTypes::DestinationUnreachable => {
                    let sent_packets_locked = sent_packets.lock().unwrap();
                    lost_packets += 1;
                    println!("9S received a destination unreachable packet from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                    addr, res_packet.get_icmp_code().0, sent_packets_locked.len(), lost_packets, lost_packets as f64 / sent_packets_locked.len() as f64 * 100f64);

                    break;
                },
                icmp::IcmpTypes::TimeExceeded => {
                    let sent_packets_locked = sent_packets.lock().unwrap();
                    lost_packets += 1;
                    println!("9S received a time exceeded packet before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                    addr, res_ip, res_packet.get_icmp_code().0, sent_packets_locked.len(), lost_packets, lost_packets as f64 / sent_packets_locked.len() as f64 * 100f64);

                    break;
                },
                _ => () // quietly skip this received packet if it is not what we were expecting
            }
        }
    })
}

fn make_icmp_timeout_thread(not_done: sync::Arc<atomic::AtomicBool>,
                            sent_packets: sync::Arc<sync::Mutex<Vec<Option<time::Instant>>>>,
                            timeout: time::Duration, addr: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut idx = 0;
        let mut total_timeout = 0;

        while not_done.load(atomic::Ordering::SeqCst) {
            // needs to acquire lock, so we do not check too often
            thread::sleep(timeout);

            let mut sent_packets_locked = sent_packets.lock().unwrap();

            while idx < sent_packets_locked.len() {
                match sent_packets_locked[idx] {
                    Some(sent_time) => {
                        let elapsed = sent_time.elapsed();

                        if elapsed > timeout {
                            total_timeout += 1;
                            println!("9S realized that a packet on its way to {} (seq num: {}) has timed out in {} > {} ms!\n\tSent {}, with {} ({:.1}%) timed out so far.",
                            addr, idx + 1, elapsed.as_millis(), timeout.as_millis(), sent_packets_locked.len(), total_timeout, total_timeout as f64 / sent_packets_locked.len() as f64 * 100f64);
                            sent_packets_locked[idx] = None;
                        }else{
                            // assumption: sent times are nondecreasing
                            // therefore, we can stop if we detect a packet
                            // that has not timed out yet
                            break;
                        }
                    },
                    None => () // continue looping
                }

                idx += 1;
            }
        }
    })
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

