// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rust_rcs_core::{
    dns::DnsConfig,
    ffi::{
        log::platform_log,
        net_ctrl::{get_active_network_info, get_dns_info, get_dns_servers, get_network_type},
    },
};

use crate::provisioning::ims_application::{ImsApplication, SignallingProtocol, TransportProto};

const LOG_TAG: &str = "librust_rcs_client";

pub enum ServiceType {
    SipD2U,
    SipD2T,
    SipsD2T,
}

impl ServiceType {
    pub fn get_string_repr(&self) -> String {
        match self {
            ServiceType::SipD2U => String::from("SIP+D2U"),

            ServiceType::SipD2T => String::from("SIP+D2T"),

            ServiceType::SipsD2T => String::from("SIPS+D2T"),
        }
    }
}

pub struct PCscfConnectionConfig {
    p: usize,
    p_cscf_addresses: Vec<(String, String)>,
    transport_proto: TransportProto,
}

impl PCscfConnectionConfig {
    pub fn new() -> PCscfConnectionConfig {
        PCscfConnectionConfig {
            p: 0,
            p_cscf_addresses: Vec::new(),
            transport_proto: TransportProto::create_default(),
        }
    }

    pub fn update_configuration(&mut self, ims_app: &ImsApplication) {
        let mut p_cscf_addresses = Vec::new();

        for (address, address_type) in ims_app.get_lbo_p_cscf_addresses() {
            p_cscf_addresses.push((String::from(address), String::from(address_type)));
        }

        let mut transport_proto = TransportProto::create_default();
        if let Some(gsma_ext) = ims_app.get_ims_gsma_extension() {
            if let Some(proto) = gsma_ext.get_info().get_transport_proto_info() {
                transport_proto = proto;
            }
        }

        self.p = 0;
        self.p_cscf_addresses = p_cscf_addresses;
        self.transport_proto = transport_proto;
    }

    /// The next P-CSCF to try, the addresses taken in turn, with how to
    /// reach it on the network in use
    pub fn get_next(
        &mut self,
    ) -> Option<(
        DnsConfig,
        ServiceType,
        String,
        Option<String>,
        Option<IpAddr>,
        Option<u16>,
    )> {
        let network_info = get_active_network_info()?;
        let network_type = get_network_type(&network_info);
        let dns_info = get_dns_info(&network_info)?;
        let dns_config = DnsConfig {
            server_addrs: get_dns_servers(&dns_info),
        };

        // 1 is Wi-Fi, 2 cellular and 3 cellular roaming
        let proto = match network_type {
            2 => &self.transport_proto.ps_signalling,
            3 => &self.transport_proto.ps_signalling_roaming,
            _ => &self.transport_proto.wifi_signalling,
        };
        let service_type = service_type(proto);

        // each address once at most, so that a list with none to use ends
        for _ in 0..self.p_cscf_addresses.len() {
            let (address, address_type) =
                &self.p_cscf_addresses[self.p % self.p_cscf_addresses.len()];
            self.p = (self.p + 1) % self.p_cscf_addresses.len();

            match parse_p_cscf_address(address, address_type) {
                Some((host, addr, port)) => {
                    return Some((dns_config, service_type, address.clone(), host, addr, port))
                }
                None => platform_log(
                    LOG_TAG,
                    format!("P-CSCF address not used: {} {}", address_type, address),
                ),
            }
        }

        None
    }
}

/// How to reach a P-CSCF over `proto`. SIP over UDP is not implemented, so
/// SIP over TCP is taken in its place, which every SIP entity supports (RFC
/// 3261 section 18)
fn service_type(proto: &SignallingProtocol) -> ServiceType {
    match proto {
        SignallingProtocol::SIPoUDP => ServiceType::SipD2T,
        SignallingProtocol::SIPoTCP => ServiceType::SipD2T,
        SignallingProtocol::SIPoTLS => ServiceType::SipsD2T,
    }
}

/// The host name, address and port of a P-CSCF address of the type given
/// (FQDN, IPv4 or IPv6), each with an optional port, an IPv6 address with a
/// port in brackets
pub fn parse_p_cscf_address(
    address: &str,
    address_type: &str,
) -> Option<(Option<String>, Option<IpAddr>, Option<u16>)> {
    let (host, port) = split_port(address)?;

    if address_type.eq_ignore_ascii_case("FQDN") {
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return None;
        }
        Some((Some(String::from(host)), None, port))
    } else if address_type.eq_ignore_ascii_case("IPv4") {
        let ip: Ipv4Addr = host.parse().ok()?;
        Some((None, Some(IpAddr::V4(ip)), port))
    } else if address_type.eq_ignore_ascii_case("IPv6") {
        let ip: Ipv6Addr = host.parse().ok()?;
        Some((None, Some(IpAddr::V6(ip)), port))
    } else {
        None
    }
}

/// `address` and the port after it, if any: `host:port`, `[v6]:port`,
/// `[v6]` or a bare IPv6 address, which has no port
fn split_port(address: &str) -> Option<(&str, Option<u16>)> {
    let address = address.trim();
    if let Some(rest) = address.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(port) => Some((host, Some(port.parse().ok()?))),
            None if after.is_empty() => Some((host, None)),
            None => None,
        };
    }

    match address.rsplit_once(':') {
        // more than one colon: a bare IPv6 address
        Some((host, _)) if host.contains(':') => Some((address, None)),
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((address, None)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::parse_p_cscf_address;

    #[test]
    fn p_cscf_addresses_are_read_with_their_ports() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        for (address, address_type, expected) in [
            (
                "pcscf.example.com",
                "FQDN",
                Some((Some("pcscf.example.com"), None, None)),
            ),
            (
                "pcscf.example.com:5061",
                "FQDN",
                Some((Some("pcscf.example.com"), None, Some(5061))),
            ),
            ("192.0.2.1", "IPv4", Some((None, Some(v4), None))),
            ("192.0.2.1:5060", "IPv4", Some((None, Some(v4), Some(5060)))),
            ("2001:db8::1", "IPv6", Some((None, Some(v6), None))),
            ("[2001:db8::1]", "IPv6", Some((None, Some(v6), None))),
            (
                "[2001:db8::1]:5061",
                "IPv6",
                Some((None, Some(v6), Some(5061))),
            ),
            ("192.0.2.1:x", "IPv4", None),
            ("pcscf.example.com", "IPv4", None),
            ("192.0.2.1", "FQDN", None),
            ("pcscf.example.com", "URI", None),
        ] {
            let parsed = parse_p_cscf_address(address, address_type);
            let expected = expected.map(|(host, addr, port)| (host.map(String::from), addr, port));
            assert_eq!(parsed, expected, "{} {}", address_type, address);
        }
    }
}
