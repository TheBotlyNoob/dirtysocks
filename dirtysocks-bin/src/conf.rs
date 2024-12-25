use base64::Engine;
use color_eyre::eyre::{ContextCompat, Result};
use std::{net::IpAddr, str::FromStr};

use smoltcp::wire::IpCidr;

#[derive(Clone, Debug)]
pub struct Conf {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpCidr>,
    pub dns: IpAddr,
    pub mtu: usize,
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<IpCidr>,
    pub endpoint: (String, u16),
}

impl Conf {
    pub fn from_str(s: &str) -> Result<Self> {
        macro_rules! n {
            ($s:literal) => {
                concat!("couldn't find `", $s, "` in config")
            };
        }

        let parsed = ini::Ini::load_from_str(s)?;

        let interface = parsed.section(Some("Interface")).context(n!("Interface"))?;

        let private_key = decode_key(interface.get("PrivateKey").context(n!("PrivateKey"))?)?;
        let addresses = interface
            .get_all("Address")
            .flat_map(IpCidr::from_str)
            .collect::<Vec<_>>();
        let dns = interface.get("DNS").context(n!("DNS"))?.parse()?;
        let mtu = interface
            .get("MTU")
            .and_then(|mtu| mtu.parse().ok())
            .unwrap_or(1280);

        let interface = Interface {
            private_key,
            addresses,
            dns,
            mtu,
        };

        let peers = parsed
            .section_all(Some("Peer"))
            .flat_map(|peer| -> Result<Peer> {
                let public_key = decode_key(peer.get("PublicKey").context(n!("PublicKey"))?)?;
                let allowed_ips = peer
                    .get_all("AllowedIPs")
                    .flat_map(IpCidr::from_str)
                    .collect::<Vec<_>>();
                let (host, port) = peer
                    .get("Endpoint")
                    .context(n!("Endpoint"))?
                    .split_once(':')
                    .context("invalid endpoint format")?;

                let port = port.parse()?;

                Ok(Peer {
                    public_key,
                    allowed_ips,
                    endpoint: (host.to_owned(), port),
                })
            })
            .collect::<Vec<_>>();

        Ok(Self { interface, peers })
    }
}

fn decode_key(encoded_key: &str) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    base64::engine::general_purpose::STANDARD.decode_slice(encoded_key, &mut key)?;
    Ok(key)
}
