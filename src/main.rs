use clap::{Arg, App, crate_version, ArgMatches};
use std::collections::{HashSet, HashMap};
use serde_derive::Deserialize;
use dnsbl::DNSBL;
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use trust_dns::client::SyncClient;
use trust_dns::udp::UdpClientConnection;

#[derive(Debug, Deserialize, Default)]
struct Input {
    dnsbls: HashSet<DNSBL>,
    ips: IPSet,
}

impl Input {
    fn new() -> Self {
        Default::default()
    }
    fn merge(&mut self, rhs: Self) {
        for dnsbl in rhs.dnsbls {
            self.dnsbls.insert(dnsbl);
        }
        self.ips.merge(rhs.ips);
    }
}

#[derive(Debug, Deserialize, Default)]
struct IPSet {
    good: HashSet<std::net::IpAddr>,
    bad: HashSet<std::net::IpAddr>,
    unknown: HashSet<std::net::IpAddr>,
}

impl IPSet {
    fn merge(&mut self, rhs: Self) {
        for el in rhs.good {
            self.good.insert(el);
        }
        for el in rhs.bad {
            self.bad.insert(el);
        }
        for el in rhs.unknown {
            self.unknown.insert(el);
        }
    }
}

fn main() -> Result<(), String> {
    let matches = App::new("dnsbl-check")
        .version(crate_version!())
        .arg(Arg::with_name("debug")
             .help("debug output, default false")
             .short("d"))
        .arg(Arg::with_name("file")
             .long("file")
             .short("f")
             .takes_value(true)
             .help("Input yaml file to use")
        ).get_matches();
    let mut input = Input::new();

    if let Some(filename) = matches.value_of("file") {
        input.merge(load_input_file(&filename)?);
    }
    input.merge(load_from_flags(&matches)?);

    { 
        let debug = matches.is_present("debug");
        let mut builder = env_logger::Builder::from_default_env();
        if debug {
            builder.filter_module("dnsbl", log::LevelFilter::Debug);
        } else {
            builder.filter_module("dnsbl", log::LevelFilter::Info);
        }
        builder.init();
    }

    // Okay, time to actually do some checking. No parallelism yet, that comes later
    let resolver = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let conn = UdpClientConnection::new(resolver).unwrap();
    let client = SyncClient::new(conn);

    // TODO: this is not the right long term way to structure this, rewrite into something better
    // abstracted
    let mut false_positives = 0;
    let mut false_negatives = 0;
    let mut check_hits = 0;

    for ip in &input.ips.good {
        for dnsbl in &input.dnsbls {
            // TODO: format dnsbl properly
            let res = dnsbl.check_ip(&client, ip)
                .map_err(|e| format!("Error lookup up '{}' on '{:?}'", ip, dnsbl))?;
            if res.listed() {
                println!("Good ip {} is listed on {:?}", ip, dnsbl);
                false_positives+=1;
            }
        }
    }

    for ip in &input.ips.bad {
        for dnsbl in &input.dnsbls {
            // TODO: format dnsbl properly
            let res = dnsbl.check_ip(&client, ip)
                .map_err(|e| format!("Error lookup up '{}' on '{:?}'", ip, dnsbl))?;
            if !res.listed() {
                false_negatives += 1;
            }
        }
    }

    Ok(())
}

fn load_input_file(filename: &str) -> Result<Input, String> {
    let f = std::fs::File::open(filename)
        .map_err(|e| format!("Could not open input file: {}", e))?;

    let input: Input = serde_yaml::from_reader(f)
        .map_err(|e| format!("Could not parse input file as yaml: {}", e))?;
    Ok(input)
}

fn load_from_flags(matches: &ArgMatches) -> Result<Input, String> {
    let mut input = Input::new();

    if let Some(bls) = matches.values_of("dnsbl") {
        for bl in bls {
            let bl = parse_bl(&bl)?;
            input.dnsbls.insert(bl);
        }
    }

    Ok(input)
}

fn parse_bl(flag: &str) -> Result<DNSBL, String> {
    let parts: Vec<&str> = flag.split(":").collect();
    match parts.len() {
        // 3 parts: 'name:host:record,record,record'
        3 => {
            let records = parts[3]
                .split(",")
                .map(|record| record.parse::<u8>())
                .collect::<Result<Vec<_>,_>>()
                .map_err(|err| format!("malformed record, must be a single octet in decimal: {}", err))?;
            Ok(DNSBL::new(parts[0].to_string(), parts[1].to_string(), records))
        }
        // 2 parts: 'name:host'
        2 => {
            Ok(DNSBL::new(parts[0].to_string(), parts[1].to_string(), Vec::new()))
        }
        // 1 part: 'host'
        1 => {
            Ok(DNSBL::new("".to_string(), parts[0].to_string(), Vec::new()))
        }
        _ => {
            Err(format!("could not parse '{}'; expected 1 to 3 colon-separated parts, not {}", flag, parts.len()))
        }
    }
}
