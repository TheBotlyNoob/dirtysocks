use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use boringtun::{
    noise::Tunn,
    x25519::{PublicKey, StaticSecret},
};
use dirtysocks::ServerOptions;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use clap::Parser;
use color_eyre::eyre::{ContextCompat, Result};

mod cli;
mod conf;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let args = cli::Args::parse();

    let conf = tokio::fs::read_to_string(args.config).await?;

    let conf: conf::Conf = conf::Conf::from_str(&conf)?;

    dbg!(&conf);

    let [peer] = &conf.peers[..] else {
        panic!("only one peer is allowed")
    };

    let mut resolver_conf = ResolverConfig::new();
    resolver_conf.add_name_server(NameServerConfig::new(
        SocketAddr::from((conf.interface.dns, 53)),
        Protocol::Udp,
    ));
    let resolver = TokioAsyncResolver::tokio(resolver_conf, ResolverOpts::default());

    let endpoint_ip = match IpAddr::from_str(&peer.endpoint.0) {
        Ok(ip) => ip,
        Err(_) => resolver
            .lookup_ip(&peer.endpoint.0)
            .await?
            .iter()
            .next()
            .context("no IPs found for endpoint address")?,
    };

    dirtysocks::Server::listen(ServerOptions {
        listener: TcpListener::bind(args.host).await.unwrap(),
        endpoint_addr: SocketAddr::from((endpoint_ip, peer.endpoint.1)),
        tunn: Tunn::new(
            StaticSecret::from(conf.interface.private_key),
            PublicKey::from(peer.public_key),
            None,
            None,
            0,
            None,
        )
        .unwrap(),
        iface_addrs: heapless::Vec::from_slice(&peer.allowed_ips)
            .ok()
            .context("too many interface addresses")?,
        timeout: Duration::from_secs(30),
        max_transmission_unit: conf.interface.mtu,
        resolver,
        user_pass: None,
    })
    .await?;

    Ok(())
}
