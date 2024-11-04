use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;

/// A usermode WireGuard implementation with a
/// SOCKS5 proxy.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    /// The `wg-quick` config file to read
    #[arg(short, long)]
    pub config: PathBuf,

    /// The socket address the SOCKS5 proxy should listen on
    #[arg(long, default_value_t = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 3000)))]
    pub host: SocketAddr,
}
