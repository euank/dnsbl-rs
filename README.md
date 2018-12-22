# DNSBL checker

DNSBL Checker is a basic cli tool that can be used to evaluate the impact of
using certain [DNS Blacklists](https://www.dnsbl.info/).


## Usage

The `dnsbl_checker` binary may be used to check an ip against a dnsbl.

```
dnsbl_checker --dnsbl "efnet:rbl.efnetrbl.org:1,2,3,5" \
              --dnsbl "sbl.spamhaus.org" \
              --dnsbl "sbl.spamhaus.org" \
              --good-ip "1.5.6.7" \
              --bad-ip "1.7.8.9" \
              --check "1.2.3.4"
```

The checker may also optionally take a `--file` flag which takes a yaml file formatted as the following.

1. DNSBLs to check
2. A list of known good ip addresses
3. A list of known bad ip addresses
4. A list of unclassified ip addresses

It will then output some basic statistics, such as the false-positive and
false-negative rate for the provided data, and the maximum list of DNSBLs which
could be used to result in the best success rate for identifying bad IPs without impacting any known good ones.

## Sample input

```yaml
dnsbls:
- name: efnet # optional, defaults to 'host', only used for display purposes
  host: rbl.efnetrbl.org
  records: [1,2,3,5] # default, everything
ips:
  good:
  - "1.2.3.4"
  bad:
  - "3.4.5.6"
  unknown:
  - "7.8.9.10"
```
