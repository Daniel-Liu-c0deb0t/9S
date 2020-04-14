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
        .expect(format!("{} is not a valid IPv4/IPv6 address or hostname!", addr).as_str());

    println!("Pinging {} ({}) with 9S's special abilities.", addr, ip_addr);
}
