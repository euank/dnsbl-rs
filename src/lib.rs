use serde_derive::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};

#[derive(Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct DNSBL {
    name: String,
    host: String,
    records: Vec<u8>,
}

pub struct CheckResult {
    reason: String,
    records: Vec<u8>,
}

impl CheckResult {
    pub fn listed(&self) -> bool {
        self.records.len() > 0
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn records(&self) -> &Vec<u8> {
        &self.records
    }
}

impl DNSBL {
    pub fn new(name: String, host: String, records: Vec<u8>) -> Self {
        let name = if name == "" { host.to_string() } else { name };

        DNSBL {
            name: name,
            host: host,
            records: records,
        }
    }

    pub fn check_ip(
        &self,
        client: &SyncClient<trust_dns::udp::UdpClientConnection>,
        ip: &IpAddr,
    ) -> Result<CheckResult, String> {
        // This is the artificial hostname to lookup in a dnsbl in order to get a result.
        // See https://tools.ietf.org/html/rfc5782#section-2
        let dnsbl_string = format!("{}.{}", reverse_ip(ip), self.host,);
        // So, DNSBLs have two different queries you can make on them:
        // 1. you can make an A record query, nice and boring. If you get something back, the
        //    ip is listed.
        // 2. You can make a TXT query for a more detailed reason, which may or may not actually
        //    give you anything back. There's also no point in making that query if the A record
        //    doesn't come back because it obviously won't be there.
        let res = client
            .query(
                &trust_dns::rr::Name::from_str(&dnsbl_string).map_err(|err| {
                    format!("malformed dnsbl host string '{}': {}", dnsbl_string, err)
                })?,
                trust_dns::rr::DNSClass::IN,
                trust_dns::rr::RecordType::A,
            )
            .map_err(|e| format!("error making query: {}", e))?;
        let records = match res.messages().into_iter().next() {
            Some(msg) => msg.answers()
                .into_iter()
                .map(|a| {
                    match a.rdata() {
                        trust_dns::rr::RData::A(ip) => ip.to_owned(),
                        _ => panic!("A record request did not get a record response"),
                    }
                })
                .collect::<Vec<_>>(),
            None => {
                return Err("no messages".to_string());
            }
        };
        if records.len() == 0 {
            // not listed
            return Ok(CheckResult {
                records: Vec::new(),
                reason: "".to_string(),
            });
        }
        // listed, let's get the reason
        //
        let res = client
            .query(
                &trust_dns::rr::Name::from_str(&dnsbl_string).map_err(|err| {
                    format!("malformed dnsbl host string '{}': {}", dnsbl_string, err)
                })?,
                trust_dns::rr::DNSClass::IN,
                trust_dns::rr::RecordType::TXT,
            )
            .map_err(|e| format!("error making query: {}", e))?;
        let reason = match res.messages().next() {
            Some(msg) => msg
                .answers()
                .into_iter()
                .map(|el| match el.rdata() {
                    trust_dns::rr::RData::TXT(data) => data
                        .txt_data()
                        .into_iter()
                        .map(|s| String::from_utf8_lossy(s))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    _ => panic!("txt request did not get txt response"),
                })
                .collect::<Vec<_>>().join("\n"),
            None => {
                return Err("no messages".to_string());
            }
        };

        let records = records.into_iter()
            .map(|record| {
                if !record.is_loopback() {
                    Err(format!("returned record was not loopback; dnsbl results should be loopback: {}", record))
                } else {
                    Ok(record.octets()[3])
                }
            })
            .collect::<Result<Vec<_>,_>>()?;

        Ok(CheckResult {
            reason: reason,
            records: records,
        })
    }
}

fn reverse_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let mut octet_strs = ip
                .octets()
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>();
            octet_strs.reverse();
            octet_strs.join(".")
        }
        IpAddr::V6(ip) => {
            let mut octet_strs = ip
                .octets()
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>();
            octet_strs.reverse();
            octet_strs.join(".")
        }
    }
}
