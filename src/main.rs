use clap::{crate_version, App, Arg, ArgMatches};
use dnsbl::{DNSBL, CheckResult};
use log::{debug, info, warn};
use std::io::Write;
use serde_derive::Deserialize;
use std::collections::{HashMap, HashSet};
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

    fn len(&self) -> usize {
        self.good.len() + self.bad.len() + self.unknown.len()
    }

    fn union(&self) -> Vec<&std::net::IpAddr> {
        let mut res: Vec<_> = self.good.union(&self.bad).collect();
        for ip in &self.unknown {
            res.push(ip)
        }
        res
    }

    fn validate(&self) -> Result<(), String> {
        // Validate that 'good', 'bad', and 'unknown' are fully disjoint.
        // Anything else would be silly and is likely a user error.
        let goodbad: Vec<_> = self.good.intersection(&self.bad).collect();
        if goodbad.len() != 0 {
            return Err(format!("'good' and 'bad' ips must be disjoint; shared '{}'", goodbad.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")));
        }
        let goodunknown: Vec<_> = self.good.intersection(&self.unknown).collect();
        if goodunknown.len() != 0 {
            return Err(format!("'good' and 'check' ips must be disjoint; shared '{}'", goodunknown.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")));
        }
        let badunknown: Vec<_> = self.bad.intersection(&self.unknown).collect();
        if badunknown.len() != 0 {
            return Err(format!("'bad' and 'check' ips must be disjoint; shared '{}'", badunknown.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")));
        }
        Ok(())
    }
}

fn main() -> Result<(), String> {
    let matches = App::new("dnsbl-check")
        .version(crate_version!())
        .arg(
            Arg::with_name("debug")
                .help("verbose output, default false")
                .short("d"),
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .help("Input yaml file to use"),
        )
        .arg(
            Arg::with_name("dnsbl")
                .long("dnsbl")
                .multiple(true)
                .short("l")
                .takes_value(true)
                .help("a dnsbl to check"),
        )
        .arg(
            Arg::with_name("good-ip")
                .multiple(true)
                .long("good-ip")
                .short("g")
                .takes_value(true)
                .help("A known-good ip"),
        )
        .arg(
            Arg::with_name("bad-ip")
                .multiple(true)
                .long("bad-ip")
                .short("b")
                .takes_value(true)
                .help("A known-bad ip"),
        )
        .arg(
            Arg::with_name("check-ip")
                .multiple(true)
                .long("check-ip")
                .short("c")
                .takes_value(true)
                .help("An ip of unknown quality"),
        )
        .get_matches();
    let mut input = Input::new();

    if let Some(filename) = matches.value_of("file") {
        input.merge(load_input_file(&filename)?);
    }
    input.merge(load_from_flags(&matches)?);

    let debug = matches.is_present("debug");
    {
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

    input.ips.validate()?;
    if input.dnsbls.len() == 0 || input.ips.len() == 0 {
        return Err("At least one dnsbl or ip must be provided".to_string());
    }

    let mut results: HashMap<std::net::IpAddr, Vec<(DNSBL, CheckResult)>> = Default::default();

    for ip in input.ips.union() {
        let mut listings = Vec::new();
        for dnsbl in &input.dnsbls {
            let res = dnsbl
                .check_ip(&client, ip)
                .map_err(|e| format!("Error lookup up '{}' on '{}': {}", ip, dnsbl, e))?;
            if res.listed() {
                listings.push((dnsbl.clone(), res));
            }
        }
        results.insert(*ip, listings);
    }
    print_stats(debug, &input.ips, results);

    Ok(())
}

fn load_input_file(filename: &str) -> Result<Input, String> {
    let f =
        std::fs::File::open(filename).map_err(|e| format!("Could not open input file: {}", e))?;

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
    if let Some(good_ips) = matches.values_of("good-ip") {
        for ip in good_ips {
            let ip = ip.parse()
                .map_err(|e| format!("invalid ip '{}': {}", ip, e))?;
            input.ips.good.insert(ip);
        }
    }
    if let Some(bad_ips) = matches.values_of("bad-ip") {
        for ip in bad_ips {
            let ip = ip.parse()
                .map_err(|e| format!("invalid ip '{}': {}", ip, e))?;
            input.ips.bad.insert(ip);
        }
    }
    if let Some(check_ips) = matches.values_of("check-ip") {
        for ip in check_ips {
            let ip = ip.parse()
                .map_err(|e| format!("invalid ip '{}': {}", ip, e))?;
            input.ips.unknown.insert(ip);
        }
    }

    Ok(input)
}

fn parse_bl(flag: &str) -> Result<DNSBL, String> {
    let parts: Vec<&str> = flag.split(":").collect();
    match parts.len() {
        // 3 parts: 'name:host:record,record,record'
        3 => {
            let records = parts[2]
                .split(",")
                .map(|record| record.parse::<u8>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    format!(
                        "malformed record, must be a single octet in decimal: {}",
                        err
                    )
                })?;
            Ok(DNSBL::new(
                parts[0].to_string(),
                parts[1].to_string(),
                records,
            ))
        }
        // 2 parts: 'name:host'
        2 => Ok(DNSBL::new(
            parts[0].to_string(),
            parts[1].to_string(),
            Vec::new(),
        )),
        // 1 part: 'host'
        1 => Ok(DNSBL::new("".to_string(), parts[0].to_string(), Vec::new())),
        _ => Err(format!(
            "could not parse '{}'; expected 1 to 3 colon-separated parts, not {}",
            flag,
            parts.len()
        )),
    }
}

fn print_stats(debug: bool, ips: &IPSet, results: HashMap<IpAddr, Vec<(DNSBL, CheckResult)>>) {
    let banned: Vec<_> = results.iter().filter(|(_, val)| val.len() > 0).collect();
    let not_banned: Vec<_> = results.iter().filter(|(_, val)| val.len() == 0).collect();
    let false_positives: Vec<_> = banned.iter().filter(|(key, _)| ips.good.contains(key)).collect();
    let false_negatives: Vec<_> = not_banned.iter().filter(|(key, _)| ips.bad.contains(key)).collect();

    let mut tw = tabwriter::TabWriter::new(Vec::new());
    tw.write_all(format!("Statistics:

Total ips\t{total}
Listed ips\t{listed}\t{listed_p}%
False positives\t{false_positives}\t{false_positives_p}%
False negatives\t{false_negatives}\t{false_negatives_p}%",
total=ips.len(),
listed=banned.len(),
listed_p=(banned.len() * 100) as f64 / ips.len() as f64,
false_positives=false_positives.len(),
false_positives_p=(false_positives.len() * 100) as f64 / ips.good.len() as f64,
false_negatives=false_negatives.len(),
false_negatives_p=(false_negatives.len() * 100) as f64 / ips.bad.len() as f64,
).as_bytes()).unwrap();
    println!("{}", String::from_utf8(tw.into_inner().unwrap()).unwrap());

    if debug {
        println!("\nFalse positive ips:\n{}", false_positives.iter().map(|(ip, _)| ip.to_string()).collect::<Vec<_>>().join("\n"));
    }
}
