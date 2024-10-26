use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use base64::Engine;
use boringtun::{
    noise::Tunn,
    x25519::{PublicKey, StaticSecret},
};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use smoltcp::wire::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    // taken from wgcf-profile.conf
    // I don't feel like parsing it in this example.

    let mut private_key = [0; 32];
    base64::engine::general_purpose::STANDARD
        .decode_slice(
            "CAgukgSnXSV/Bf6pubM/GdW1QZ/bmjBbsI2LryTJwk4=",
            &mut private_key,
        )
        .unwrap();
    let mut public_key = [0; 32];
    base64::engine::general_purpose::STANDARD
        .decode_slice(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            &mut public_key,
        )
        .unwrap();

    dirtysocks::Server::new(
        TcpListener::bind("0.0.0.0:3000").await.unwrap(),
        Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(public_key),
            None,
            None,
            0,
            None,
        )
        .unwrap(),
        SocketAddr::from((Ipv4Addr::from([162, 159, 192, 1]), 2408)),
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default()),
        Duration::from_secs(20),
        None,
        heapless::Vec::from_slice(&[
            IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 0, 2).into(), 32)),
            IpCidr::Ipv6(Ipv6Cidr::new(
                Ipv6Addr::from_str("2606:4700:110:8a92:f108:c887:d02e:1b61")
                    .unwrap()
                    .into(),
                128,
            )),
        ])
        .unwrap(),
    )
    .await
    .unwrap()
    .listen()
    .await
    .unwrap();
}
