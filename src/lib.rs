#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use handler::{Authorized, Connection, Initial, Piping};
use hickory_resolver::TokioAsyncResolver;
use smoltcp::{
    iface::{self, Config, SocketSet},
    socket::{
        tcp::{self, SocketBuffer},
        AnySocket, Socket,
    },
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    convert::Infallible,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
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
    pub socket_set: Arc<Mutex<SocketSet<'static>>>,
    pub resolver: TokioAsyncResolver,
    pub timeout: Duration,
    pub user_pass: Option<UserPass>,
    next_ephemeral_port: Arc<AtomicU16>,
}

type FoConn<T> = FuturesUnordered<Pin<Box<dyn Future<Output = Result<T, Error>> + Send>>>;

// TODO: reuse sockets
impl Server {
    // TODO: use builder for this
    pub async fn new(
        listener: TcpListener,
        tunn: Tunn,
        endpoint_addr: SocketAddr,
        resolver: TokioAsyncResolver,
        timeout: Duration,
        user_pass: Option<UserPass>,
        iface_addr: IpAddr,
    ) -> Result<Self, Error> {
        let peer_conn = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        peer_conn.connect(endpoint_addr).await?;

        let peer = Peer::new(tunn, endpoint_addr, peer_conn);
        let mut device = WgDevice(peer.queues.clone());

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut device, Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(iface_addr), 32))
                .unwrap();
        });

        Ok(Self {
            listener,
            peer: Some(peer),
            device,
            iface,
            socket_set: Arc::new(Mutex::new(SocketSet::new(Vec::new()))),
            resolver,
            timeout,
            user_pass,
            next_ephemeral_port: Arc::new(AtomicU16::new(1)),
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
        let mut piping: FoConn<(Option<usize>, Connection<Piping>)> = FuturesUnordered::new();

        loop {
            poll_next = self.poll_iface();

            tokio::select! {
                biased;

                Ok((stream, client_addr)) = self.listener.accept() =>
                    initial_connections.push(Box::pin(self.new_conn(
                        stream,
                        client_addr,
                    ))),

                Some(conn) = connections_authorized.next() => {
                    let (addr, conn) = conn.unwrap();
                    piping.push(Box::pin(self.conn_authorized(
                        addr,
                        conn,
                    )));
                }
                Some(conn) = initial_connections.next() => {
                    let conn = conn.unwrap();
                    connections_authorized.push(Box::pin(conn.handle_request()));
                }


                Some(pipe) = piping.next() => {
                    let (sent_len, pipe) = match pipe {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(?e, "error piping");
                            continue;
                        }
                    };

                    if sent_len == Some(0) {
                        // the connection has been closed
                        self.socket_set.lock().unwrap().get_mut::<tcp::Socket>(pipe.socket_handle).close();
                    } else {
                        piping.push(self.pipe(sent_len, pipe));
                    }
                }
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
            SocketBuffer::new(vec![0; 8 * 1024]),
            SocketBuffer::new(vec![0; 8 * 1024]),
        );

        let socket_handle = self.socket_set.lock().unwrap().add(socket);

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
    ) -> impl Future<Output = Result<(Option<usize>, Connection<Piping>), Error>> {
        tracing::info!(?addr, "connection authorized");

        {
            let mut socket_set = self.socket_set.lock().unwrap();

            let socket = socket_set.get_mut::<tcp::Socket>(conn.socket_handle);

            socket
                .connect(
                    self.iface.context(),
                    (IpAddress::from(addr.ip()), addr.port()),
                    self.next_ephemeral_port.fetch_add(1, Ordering::SeqCst),
                )
                .unwrap();
        }

        conn.pipe(None)
    }

    fn pipe(
        &mut self,
        mut sent_len: Option<usize>,
        mut pipe: Connection<Piping>,
    ) -> Pin<
        Box<dyn Future<Output = Result<(Option<usize>, Connection<Piping>), Error>> + Send + Sync>,
    > {
        let mut socket_set = self.socket_set.lock().unwrap();

        let socket = socket_set.get_mut::<tcp::Socket>(pipe.socket_handle);

        if let Some(sent_len_) = sent_len {
            if socket.may_send() {
                tracing::info!(?sent_len, "sending through wireguard");
                assert_eq!(
                    socket.send_slice(&pipe.buf[0..sent_len_]).unwrap(),
                    sent_len_
                );
                sent_len = None;
            }
        }

        if dbg!(socket.can_recv()) {
            tracing::info!("attempting to recv");
            Box::pin(
                socket
                    .recv(|buf| {
                        tracing::error!(len = buf.len(), "recv'd");
                        pipe.buf[0..buf.len()].copy_from_slice(buf);

                        (buf.len(), pipe.pipe(Some(buf.len())))
                    })
                    .unwrap(),
            )
        } else if sent_len.is_none() {
            // we sent what we wanted to--no use in waiting for a response to call `pipe` again
            Box::pin(pipe.pipe(None))
        } else {
            // keep polling this pipe until we can read more
            Box::pin(async move {
                tracing::info!("polling");
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok((sent_len, pipe))
            })
        }
    }

    fn poll_iface(&mut self) -> tokio::time::Instant {
        tracing::info!("polling iface");
        let std_now = std::time::Instant::now();
        let smoltcp_now = smoltcp::time::Instant::from(std_now);
        let tokio_now = tokio::time::Instant::from_std(std_now);

        let delay = {
            let mut socket_set = self.socket_set.lock().unwrap();

            self.iface
                .poll(smoltcp_now, &mut self.device, &mut socket_set);

            self.iface.poll_delay(smoltcp_now, &socket_set)
        };

        tokio_now + Duration::from_micros(delay.map_or(0, |d| d.total_micros()))
    }
}
