#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use handler::{Authorized, Connection, Piping, SendToClient};
use hickory_resolver::TokioAsyncResolver;
use smoltcp::{
    iface::{self, Config, SocketSet},
    socket::tcp::{self, SocketBuffer},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};

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
    #[error("error waiting for future: {0}")]
    JoinError(#[from] tokio::task::JoinError),
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

        let mut initial_connections: JoinSet<Result<Connection<Authorized>, Error>> =
            JoinSet::new();
        let mut connections_authorized: JoinSet<Result<(SocketAddr, Connection<Piping>), Error>> =
            JoinSet::new();
        let mut piping: JoinSet<Result<(), Error>> = JoinSet::new();

        loop {
            tokio::select! {
                biased;

                Ok((stream, client_addr)) = self.listener.accept() => {
                    initial_connections.spawn(Box::pin(self.new_conn(
                        stream,
                        client_addr,
                    )));
                }

                Some(conn) = connections_authorized.join_next() => {
                    match conn? {
                        Ok((addr, conn)) => {
                            piping.spawn(Box::pin(self.pipe(
                                 addr, conn
                            )));
                        }
                        Err(e) => tracing::warn!(?e, "error in authorized connection"),
                    }
                }

                Some(conn) = initial_connections.join_next() => {
                    match conn? {
                        Ok(conn) => {
                            connections_authorized.spawn(Box::pin(conn.handle_request()));
                        },
                        Err(e) => tracing::warn!(?e, "error in initial connection"),
                    }
                }

                Some(conn) = piping.join_next() => {
                    if let Err(e) = conn? {
                        tracing::warn!(?e, "error in piping connection");
                    }
                }

               () = tokio::time::sleep_until(poll_next) => {
                    poll_next = self.poll_iface();
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
    fn pipe(
        &mut self,
        addr: SocketAddr,
        mut pipe: Connection<Piping>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        tracing::info!(?addr, "connection authorized");

        {
            let mut socket_set = self.socket_set.lock().unwrap();

            let socket = socket_set.get_mut::<tcp::Socket>(pipe.socket_handle);

            socket
                .connect(
                    self.iface.context(),
                    (IpAddress::from(addr.ip()), addr.port()),
                    dbg!(self.next_ephemeral_port.fetch_add(1, Ordering::SeqCst)),
                )
                .unwrap();
        }

        let pipe = Arc::new(pipe);
        PipeFut {
            fut: Box::pin(pipe.clone().pipe([0; 8 * 1024], None)),
            pipe,
            sending: false,
            socket_set: self.socket_set.clone(),
            need_to_send_to_wg: None,
        }
    }

    fn poll_iface(&mut self) -> tokio::time::Instant {
        let std_now = std::time::Instant::now();
        let smoltcp_now = smoltcp::time::Instant::from(std_now);
        let tokio_now = tokio::time::Instant::from_std(std_now);

        let delay = {
            let mut socket_set = self.socket_set.lock().unwrap();

            self.iface
                .poll(smoltcp_now, &mut self.device, &mut socket_set);

            self.iface.poll_delay(smoltcp_now, &socket_set)
        };

        tokio_now + Duration::from_micros(delay.map_or(0, |d| d.total_micros().saturating_sub(50)))
    }
}

struct PipeFut {
    pipe: Arc<Connection<Piping>>,
    fut: Pin<Box<dyn Future<Output = Result<([u8; 8 * 1024], Option<usize>), Error>> + Send>>,
    sending: bool,
    socket_set: Arc<Mutex<SocketSet<'static>>>,

    need_to_send_to_wg: Option<([u8; 8 * 1024], SendToClient)>,
}

impl Future for PipeFut {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self {
            ref pipe,
            ref mut fut,
            ref mut sending,
            ref mut socket_set,
            ref mut need_to_send_to_wg,
        } = *self;

        let mut socket_set = socket_set.lock().unwrap();

        let socket = socket_set.get_mut::<tcp::Socket>(pipe.socket_handle);

        socket.register_recv_waker(cx.waker());
        socket.register_send_waker(cx.waker());

        if let Some((buf, SendToClient(to_send))) = need_to_send_to_wg.take() {
            if socket.can_send() {
                tracing::info!(?to_send, "sending through wireguard");
                assert_eq!(socket.send_slice(&buf[0..to_send]).unwrap(), to_send);
            } else {
                *need_to_send_to_wg = Some((buf, SendToClient(to_send)));
            }
        }

        let res = fut.as_mut().poll(cx);
        match res {
            Poll::Ready(to_send) => {
                let (buf, to_send) = to_send?;

                dbg!(&to_send);

                if let Some(to_send) = to_send {
                    if dbg!(*sending) {
                        // this means there's still stuff left in the buffer to send
                        *fut = Box::pin(pipe.clone().pipe(buf, Some(SendToClient(to_send))));
                    } else {
                        if to_send == 0 {
                            tracing::info!("closing connection");
                            socket.close();
                            return Poll::Ready(Ok(()));
                        }
                        if dbg!(socket.can_send()) {
                            tracing::info!(?to_send, "sending through wireguard");
                            assert_eq!(socket.send_slice(&buf[0..to_send]).unwrap(), to_send);
                        } else {
                            *need_to_send_to_wg = Some((buf, SendToClient(to_send)));
                        }
                    }
                }

                *sending = false;
                *fut = Box::pin(pipe.clone().pipe(buf, None));
            }
            Poll::Pending if *sending => {
                tracing::info!("waiting to send");
                return Poll::Pending;
            }
            Poll::Pending => {
                if dbg!(socket.can_recv()) {
                    tracing::info!("attempting to recv");
                    let new_fut = socket
                        .recv(|buf| {
                            tracing::error!(len = buf.len(), "recv'd");
                            let mut new_buf = [0; 8 * 1024];
                            let to_read = buf.len().min(new_buf.len());
                            new_buf[0..to_read].copy_from_slice(buf);

                            (
                                to_read,
                                Box::pin(pipe.clone().pipe(new_buf, Some(SendToClient(buf.len())))),
                            )
                        })
                        .unwrap();
                    *sending = true;
                    *fut = new_fut;
                }
            }
        }

        tracing::error!("wowza");

        Poll::Pending
    }
}
