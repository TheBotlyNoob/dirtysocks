use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
    )
    .await
    .unwrap()
    .listen()
    .await
    .unwrap();
}
