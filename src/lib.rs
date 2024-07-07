#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use handler::{Authorized, Connection, Initial, Piping};
use hickory_resolver::TokioAsyncResolver;
use smoltcp::{
    iface::{self, Config, SocketSet},
    socket::tcp::{self, SocketBuffer},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{convert::Infallible, net::SocketAddr, pin::Pin, time::Duration};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub mod wg;
use wg::{Peer, WgDevice};

pub mod handler;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("authentication method not found")]
    AuthMethodNotFound,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("invalid version")]
    InvalidVersion,
    #[error("incomplete request parsing")]
    IncompleteRead,
    #[error("unexpected end of input")]
    UnexpectedEOI,
    #[error("invalid address type")]
    InvalidAddressType,
    #[error("invalid command type")]
    InvalidCommandType,
    #[error("invalid string")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("dns lookup error: {0}")]
    DnsLookup(#[from] hickory_resolver::error::ResolveError),
    #[error("no such host")]
    NoSuchHost,
    #[error("timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
impl From<untrusted::EndOfInput> for Error {
    fn from(_: untrusted::EndOfInput) -> Self {
        Self::UnexpectedEOI
    }
}

#[derive(Clone, Debug)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

/// A socks5 server implementation, sending data to a single `WireGuard` peer.
pub struct Server {
    pub listener: TcpListener,
    pub peer: Option<wg::Peer>,
    pub device: wg::WgDevice,
    pub iface: iface::Interface,
    pub socket_set: SocketSet<'static>,
    pub resolver: TokioAsyncResolver,
    pub timeout: Duration,
    pub user_pass: Option<UserPass>,
}

type FoConn<T> = FuturesUnordered<Pin<Box<dyn Future<Output = Result<T, Error>> + Send>>>;

impl Server {
    pub async fn new(
        listener: TcpListener,
        tunn: Tunn,
        wg_addr: SocketAddr,
        resolver: TokioAsyncResolver,
        timeout: Duration,
        user_pass: Option<UserPass>,
    ) -> Result<Self, Error> {
        let peer_conn = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        peer_conn.connect(wg_addr).await?;

        let peer = Peer::new(tunn, wg_addr, peer_conn);
        let mut device = WgDevice(peer.queues.clone());

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut device, Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24))
                .unwrap();
        });

        Ok(Self {
            listener,
            peer: Some(peer),
            device,
            iface,
            socket_set: SocketSet::new(Vec::new()),
            resolver,
            timeout,
            user_pass,
        })
    }

    #[allow(clippy::redundant_pub_crate)]
    pub async fn listen(mut self) -> Result<Infallible, Error> {
        tracing::info!("SOCKS5 server started");
        if self.user_pass.is_some() {
            tracing::info!("using username/password authentication");
        } else {
            tracing::info!("no authentication required");
        }

        let mut peer = self.peer.take().unwrap();
        tokio::spawn(async move { peer.begin_device().await.unwrap() });

        let mut poll_next = tokio::time::Instant::now();

        let mut initial_connections: FoConn<Connection<Authorized>> = FuturesUnordered::new();
        let mut connections_authorized: FoConn<(SocketAddr, Connection<Piping>)> =
            FuturesUnordered::new();
        let mut piping: FoConn<(usize, Connection<Piping>)> = FuturesUnordered::new();

        loop {
            tokio::select! {
                () = tokio::time::sleep_until(poll_next) =>
                    poll_next = self.poll_iface(),
                Some(pipe) = piping.next() => {
                    let (sent_len, pipe) = pipe?;
                    if let Some(pipe) = self.pipe(sent_len, pipe) {
                        piping.push(pipe);
                    }
                }
                Some(conn) = connections_authorized.next() => {
                    let (addr, conn) = conn?;
                    piping.push(Box::pin(self.conn_authorized(
                        addr,
                        conn,
                    )));
                }
                Some(conn) = initial_connections.next() => {
                    let conn = conn?;
                    connections_authorized.push(Box::pin(conn.handle_request()));
                }
                Ok((stream, client_addr)) = self.listener.accept() =>
                    initial_connections.push(Box::pin(self.new_conn(
                        stream,
                        client_addr,
                    ))),
            }
        }
    }

    fn new_conn(
        &mut self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> impl Future<Output = Result<Connection<Authorized>, Error>> {
        tracing::info!(?client_addr, "new connection");

        let socket = tcp::Socket::new(
            SocketBuffer::new(Vec::with_capacity(8 * 1024)),
            SocketBuffer::new(Vec::with_capacity(8 * 1024)),
        );

        let socket_handle = self.socket_set.add(socket);

        Connection::new(
            stream,
            client_addr,
            socket_handle,
            self.resolver.clone(),
            self.timeout,
            self.user_pass.clone(),
        )
        .init_conn()
    }

    fn conn_authorized(
        &mut self,
        addr: SocketAddr,
        conn: Connection<Piping>,
    ) -> impl Future<Output = Result<(usize, Connection<Piping>), Error>> {
        tracing::info!(?addr, "connection authorized");

        let socket = self.socket_set.get_mut::<tcp::Socket>(conn.socket_handle);

        socket
            .connect(
                self.iface.context(),
                (IpAddress::from(addr.ip()), addr.port()),
                49154,
            )
            .unwrap();

        conn.pipe(None)
    }

    fn pipe(
        &mut self,
        sent_len: usize,
        pipe: Connection<Piping>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<(usize, Connection<Piping>), Error>> + Send + Sync>>>
    {
        let socket = self.socket_set.get_mut::<tcp::Socket>(pipe.socket_handle);

        //tracing::debug!(?sent_len, can_send = socket.can_send(), "");

        if socket.can_send() {
            tracing::info!(?sent_len, "sending through wireguard");
            //assert_eq!(socket.send_slice(&pipe.buf[0..sent_len]).unwrap(), sent_len);
            // Box::pin(pipe.pipe(None))
            None
        } else {
            Some(Box::pin(async move { Ok((sent_len, pipe)) }))
        }
    }

    fn poll_iface(&mut self) -> tokio::time::Instant {
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.socket_set);

        let delay = self.iface.poll_delay(Instant::now(), &self.socket_set);

        tokio::time::Instant::now() + Duration::from_micros(delay.map_or(0, |d| d.total_micros()))
    }
}