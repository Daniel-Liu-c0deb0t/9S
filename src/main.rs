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
// we only have 16 bits to store the sequence number for each packet
// future work: expand number of bits or recycle used sequence numbers
const DEFAULT_ITER: usize = u16::max_value() as usize;
const HELP_MSG: &str = "To build and run: ./9S [optional args] address

Required args:
\t address : IPv4/IPv6 address or hostname (autodetected), where the ICMP packets will be sent.

Optional args:
\t--ttl ttl : Sets the time to live (hop limit) for all packets. Limitation: only works for IPv4. Default: 64.
\t--timeout timeout_ms : Sets the time limit (in milliseconds) before a packet is categorized as timed out. Default: 5000 ms.
\t--delay delay_ms : Sets the delay (in milliseconds) between sending each packet. Default: 1000 ms.
\t--iter iter : Sets the number of packets to be sent. Default: keep sending and don't stop.
\t-h or --help : Prints this message.

Each ICMP packet is strictly checked for matching identifiers, etc., so multiple programs can be sending pings at the same time.";

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

    // very basic argument parser
    // future work: use a dedicated library
    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                i += 1;
                ttl = args[i].parse::<u8>().expect(format!("{} is not a valid TTL value! 9S unhappy :( ", args[i]).as_str());
            },
            "--timeout" => {
                i += 1;
                timeout_ms = args[i].parse::<u64>().expect(format!("{} is not a valid timeout value in ms! 9S unhappy :( ", args[i]).as_str());
            },
            "--delay" => {
                i += 1;
                delay_ms = args[i].parse::<u64>().expect(format!("{} is not a valid delay value in ms! 9S unhappy :( ", args[i]).as_str());
            },
            "--iter" => {
                i += 1;
                iterations = args[i].parse::<usize>().expect(format!("{} is not a valid number of iterations! 9S unhappy :( ", args[i]).as_str());
            },
            "-h" | "--help" => {
                println!("{}", HELP_MSG);
                std::process::exit(0);
            },
            _ => {
                if pos_args > pos_args_max {
                    panic!("Too many arguments! 9S unhappy :( ");
                }else{
                    addr = &args[i];
                    pos_args += 1;
                }
            }
        }

        i += 1;
    }

    if pos_args != pos_args_max {
        eprintln!("You are missing an argument! 9S unhappy :(");
        println!("{}", HELP_MSG);
        std::process::exit(0);
    }

    ping(addr, iterations, ttl, timeout_ms, delay_ms);
}

/// Pings a certain IPv4/IPv6 address or hostname, and prints output to stdout.
///
/// # Arguments
/// * `addr` - An IPv4/IPv6 address or hostname string.
/// * `iterations` - Number of packets to send.
/// * `ttl` - Time to live.
/// * `timeout_ms` - How long to wait for an echo reply when an echo request is sent.
/// * `delay_ms` - Delay between sending each packet.
fn ping(addr: &String, iterations: usize, ttl: u8, timeout_ms: u64, delay_ms: u64) {
    let timeout = time::Duration::from_millis(timeout_ms);
    let delay = time::Duration::from_millis(delay_ms);

    let ip_addr = match net::IpAddr::from_str(addr) {
        Ok(ip) => {
            println!("Pinging {} with 9S's special abilities.", ip);
            ip
        },
        Err(_) => {
            // at this point, ip_addr must be a hostname or an invalid IPv4/IPv6 address
            // workaround to do DNS lookup using SocketAddr; port number does not matter
            let ip = (addr.as_str(), 80u16).to_socket_addrs()
                .expect(format!("{} is not a valid IPv4/IPv6 address or hostname! 9S unhappy :( ", addr).as_str())
                .next()
                .unwrap()
                .ip();
            println!("Pinging {} ({}) with 9S's special abilities.", addr, ip);
            ip
        }
    };

    // use process id to identify ICMP packets that were sent from this process
    // future work: handle process IDs larger than u16::max_value()
    let identifier = std::process::id() as u16;

    let (mut sender, receiver) = match ip_addr {
        net::IpAddr::V4(_) => {
            // note: must use Layer4 since pnet does not support IPv6 Layer3
            // it will take care of creating sockets and wrapping our ICMP packets with IPv4/IPv6 packets before sending
            // the biggest limitation of this is that we cannot obtain the ttl of received packets
            transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Icmp)))
                .expect("Unable to open transport channel! 9S unhappy :( ")
        },
        net::IpAddr::V6(_) => {
            transport_channel(1024, TransportChannelType::Layer4(
                    TransportProtocol::Ipv6(ip::IpNextHeaderProtocols::Icmpv6)))
                .expect("Unable to open transport channel! 9S unhappy :( ")
        }
    };

    // this will set the ttl for all packets
    // unfortunately, pnet does not support setting the ttl on IPv6
    if ip_addr.is_ipv4() {
        sender.set_ttl(ttl).unwrap();
    }

    // keep track of whether this process are exiting
    // note: use reference counting to share this variable across threads
    let not_done = sync::Arc::new(atomic::AtomicBool::new(true));
    // note: we use a Mutex instead of AtomicUsize for flexibility
    let total_packets = sync::Arc::new(sync::Mutex::new(0usize));

    // handle exit signal, which will stops the threads
    make_exit_handler(not_done.clone());

    // create a separate thread to receive packets in any order
    // the main thread will handle sending
    let receiver_thread = match ip_addr {
        net::IpAddr::V4(_) => make_icmp_receiver_thread(not_done.clone(), receiver, total_packets.clone(), identifier, timeout, addr.clone()),
        net::IpAddr::V6(_) => make_icmpv6_receiver_thread(not_done.clone(), receiver, total_packets.clone(), identifier, timeout, addr.clone())
    };

    let mut curr_time = time::Instant::now();
    // just for the first iteration
    let mut start = true;

    while not_done.load(atomic::Ordering::SeqCst) {
        // very basic loop to send packets with a delay
        if start || curr_time.elapsed() > delay {
            {
                // incrementing total_packets and sending the packet must happen atomically
                // if we are not careful in ordering our operations, a sent packet may be
                // received before total_packets is incremented
                let mut total_packets_sent = total_packets.lock().unwrap();
                *total_packets_sent += 1;

                // 8 is the ICMP header size
                let mut icmp_buffer = [0u8; 8 + DEFAULT_PAYLOAD_SIZE];

                match ip_addr {
                    net::IpAddr::V4(_) => {
                        let packet = make_icmp_packet(&mut icmp_buffer, identifier, (*total_packets_sent) as u16);
                        sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy :( ");
                    },
                    net::IpAddr::V6(ip) => {
                        let packet = make_icmpv6_packet(ip, &mut icmp_buffer, identifier, (*total_packets_sent) as u16);
                        sender.send_to(packet, ip_addr).expect("Error in sending packet! 9S unhappy :( ");
                    }
                }

                if *total_packets_sent >= iterations {
                    break;
                }
            }

            start = false;
            curr_time = time::Instant::now();
        }
    }

    // check if we are exiting because we finished enough iterations
    // it is possible to reach this point without finishing enough iterations due to Ctrl+C
    if not_done.load(atomic::Ordering::SeqCst) {
        // if we have finished enough iterations then we need to wait for packets until timeout
        // otherwise, we don't wait because we received an exit signal
        match timeout.checked_sub(delay) {
            Some(time) => thread::sleep(time),
            None => ()
        }

        not_done.store(false, atomic::Ordering::SeqCst);
    }

    // print final statistics
    let (received, lost) = receiver_thread.join().unwrap();
    let total = *total_packets.lock().unwrap();
    let timedout = if lost + received > total {0} else {total - received - lost};
    println!("\nDone! 9S sent {} packets total to {}.\n\t9S received {} ({:.1}%), lost {} ({:.1}%), and realized that {} ({:.1}%) timed out.",
    total, addr, received, received as f64 / total as f64 * 100f64, lost, lost as f64 / total as f64 * 100f64, timedout, timedout as f64 / total as f64 * 100f64);
}

/// Creates a separate to concurrently receive ICMP packets that are sent, and returns a JoinHandle that
/// allows the received packets count and lost packets count to be accessed.
///
/// # Arguments
/// * `not_done` - Whether this process is exiting.
/// * `receiver` - TransportReceiver for receiving packets.
/// * `total_packets` - Number of packets sent so far.
/// * `identifier` - A number uniquely identifying this process.
/// * `timeout` - How long to wait for an echo reply when an echo request is sent.
/// * `addr` - Address of where to send packets. This is mainly used for printing to stdout.
fn make_icmp_receiver_thread(not_done: sync::Arc<atomic::AtomicBool>,
                             mut receiver: TransportReceiver,
                             total_packets: sync::Arc<sync::Mutex<usize>>,
                             identifier: u16,
                             timeout: time::Duration,
                             addr: String) -> thread::JoinHandle<(usize, usize)> {
    thread::spawn(move || {
        let mut receiver_iter = icmp_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;
        // HashSet to keep track of duplicate packets
        let mut received = collections::HashSet::new();
        let receiver_delay = time::Duration::from_millis(100);

        while not_done.load(atomic::Ordering::SeqCst) {
            // receiver_delay should be low to keep this thread responsive to not_done changes
            let next_res = receiver_iter.next_with_timeout(receiver_delay)
                .expect("Error receiving packet! 9S unhappy :( ");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue
            };

            let curr_time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis();
            // we don't care if this is changed by the main thread (we want consistency in the
            // printed results), so just read it once
            let total_packets_sent = {*total_packets.lock().unwrap()};

            match res_packet.get_icmp_type() {
                icmp::IcmpTypes::EchoReply => {
                    let (res_identifier, res_seq_num, res_send_time) = read_payload(res_packet.payload());

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            let elapsed_ms = curr_time - res_send_time;

                            // a packet is timed out even if we receive it after the timeout
                            if elapsed_ms > timeout.as_millis() {
                                println!("9S received timed out packet (seq num: {}) from {} in {} ms!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, elapsed_ms, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }else{
                                total_rtt += elapsed_ms;
                                received_packets += 1;
                                println!("9S received packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                    res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                },
                icmp::IcmpTypes::DestinationUnreachable => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..24 is the IPv4 header,
                    // 24..28 is the ICMP header, and 28..32 is the identifier and sequence number
                    let (res_identifier, res_seq_num) = read_payload_id(&res_packet.payload()[28..32]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            lost_packets += 1;
                            println!("9S received a destination unreachable packet (seq num: {}) from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                },
                icmp::IcmpTypes::TimeExceeded => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..24 is the IPv4 header,
                    // 24..28 is the ICMP header, and 28..32 is the identifier and sequence number
                    let (res_identifier, res_seq_num) = read_payload_id(&res_packet.payload()[28..32]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            lost_packets += 1;
                            println!("9S received a time exceeded packet (seq num: {}) before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_ip, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                },
                _ => () // quietly skip this received packet if it is not what we were expecting
            }
        }

        (received_packets, lost_packets)
    })
}

/// Creates a separate to concurrently receive ICMPv6 packets that are sent, and returns a JoinHandle that
/// allows the received packets count and lost packets count to be accessed.
///
/// # Arguments
/// * `not_done` - Whether this process is exiting.
/// * `receiver` - TransportReceiver for receiving packets.
/// * `total_packets` - Number of packets sent so far.
/// * `identifier` - A number uniquely identifying this process.
/// * `timeout` - How long to wait for an echo reply when an echo request is sent.
/// * `addr` - Address of where to send packets. This is mainly used for printing to stdout.
fn make_icmpv6_receiver_thread(not_done: sync::Arc<atomic::AtomicBool>,
                             mut receiver: TransportReceiver,
                             total_packets: sync::Arc<sync::Mutex<usize>>,
                             identifier: u16,
                             timeout: time::Duration,
                             addr: String) -> thread::JoinHandle<(usize, usize)> {
    thread::spawn(move || {
        let mut receiver_iter = icmpv6_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;
        // HashSet to keep track of duplicate packets
        let mut received = collections::HashSet::new();
        let receiver_delay = time::Duration::from_millis(100);

        while not_done.load(atomic::Ordering::SeqCst) {
            // receiver_delay should be low to keep this thread responsive to not_done changes
            let next_res = receiver_iter.next_with_timeout(receiver_delay)
                .expect("Error receiving packet! 9S unhappy :( ");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue
            };

            let curr_time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis();
            // we don't care if this is changed by the main thread (we want consistency in the
            // printed results), so just read it once
            let total_packets_sent = {*total_packets.lock().unwrap()};

            match res_packet.get_icmpv6_type() {
                icmpv6::Icmpv6Types::EchoReply => {
                    let (res_identifier, res_seq_num, res_send_time) = read_payload(res_packet.payload());

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            let elapsed_ms = curr_time - res_send_time;
                            total_rtt += elapsed_ms;

                            // a packet is timed out even if we receive it after the timeout
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
                    // not our packet, not our problem
                },
                icmpv6::Icmpv6Types::DestinationUnreachable => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..44 is the IPv6 header,
                    // 44..48 is the ICMPv6 header, and 48..52 is the identifier and sequence number
                    let (res_identifier, res_seq_num) = read_payload_id(&res_packet.payload()[48..52]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            lost_packets += 1;
                            println!("9S received a destination unreachable packet (seq num: {}) from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_packet.get_icmpv6_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                },
                icmpv6::Icmpv6Types::TimeExceeded => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..44 is the IPv6 header,
                    // 44..48 is the ICMPv6 header, and 48..52 is the identifier and sequence number
                    let (res_identifier, res_seq_num) = read_payload_id(&res_packet.payload()[48..52]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent {
                        if received.contains(&res_seq_num) {
                            println!("9S received a duplicate packet (seq num: {}) from {}!", res_seq_num, addr);
                        }else{
                            lost_packets += 1;
                            println!("9S received a time exceeded packet (seq num: {}) before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_ip, res_packet.get_icmpv6_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                },
                _ => () // quietly skip this received packet if it is not what we were expecting
            }
        }

        (received_packets, lost_packets)
    })
}

/// Creates a handler for SIGINT/SIGTERM (Ctrl-C) events.
///
/// # Arguments
/// * `not_done` - Whether this process is exiting.
fn make_exit_handler(not_done: sync::Arc<atomic::AtomicBool>) {
    ctrlc::set_handler(move || not_done.store(false, atomic::Ordering::SeqCst)).unwrap();
}

/// Creates an ICMP packet.
///
/// It is important to call this right before sending the packet,
/// since this function will record the current time.
///
/// # Arguments
/// * `icmp_buffer` - Empty buffer with enough size for the packet.
/// * `identifier` - Unique identifier for this process.
/// * `seq_num` - Sequence number for this packet.
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

/// Creates an ICMPv6 packet.
///
/// It is important to call this right before sending the packet,
/// since this function will record the current time.
///
/// # Arguments
/// * `dest` - Destination IPv6 address. Only used for the checksum.
/// * `icmp_buffer` - Empty buffer with enough size for the packet.
/// * `identifier` - Unique identifier for this process.
/// * `seq_num` - Sequence number for this packet.
fn make_icmpv6_packet(dest: net::Ipv6Addr, icmp_buffer: &mut [u8], identifier: u16, seq_num: u16) -> icmpv6::Icmpv6Packet {
    let mut icmp_packet = icmpv6::MutableIcmpv6Packet::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmpv6::Icmpv6{
        icmpv6_type: icmpv6::Icmpv6Types::EchoRequest,
        icmpv6_code: icmpv6::Icmpv6Code::new(0),
        checksum: 0,
        payload: make_payload(identifier, seq_num)
    });

    icmp_packet.set_checksum(icmpv6::checksum(
            &icmp_packet.to_immutable(), &net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), &dest));
    icmp_packet.consume_to_immutable()
}

/// Creates a payload vector of bytes.
///
/// This function records the current time.
///
/// # Arguments
/// * `identifier` - Unique identifier for this process.
/// * `seq_num` - Sequence number for the packet.
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

/// Returns a tuple containing the identifier, sequence number,
/// and send time (in milliseconds) for a packet's payload.
///
/// # Arguments
/// * `payload` - Payload of a packet.
fn read_payload(payload: &[u8]) -> (u16, u16, u128) {
    let send_time = unsafe {
        let num = 0u128;
        let mut arr = mem::transmute::<u128, [u8; 16]>(num);
        arr.copy_from_slice(&payload[4..20]);
        mem::transmute::<[u8; 16], u128>(arr)
    };

    (payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
     payload[2] as u16 + ((payload[3] as u16) << 8), // sequence number
     send_time)
}

/// Returns a tuple containing the identifier and sequence number for a packet's payload.
///
/// # Arguments
/// * `payload` - Payload of a packet.
fn read_payload_id(payload: &[u8]) -> (u16, u16) {
    (payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
     payload[2] as u16 + ((payload[3] as u16) << 8)) // sequence number
}

