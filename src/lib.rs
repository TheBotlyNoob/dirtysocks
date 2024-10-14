#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use handler::{Connection, Piping};
use hickory_resolver::TokioAsyncResolver;
use smoltcp::{
    iface::{self, Config, SocketHandle, SocketSet},
    socket::tcp::{self, SocketBuffer},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    convert::Infallible,
    future::{poll_fn, Future},
    net::{IpAddr, SocketAddr},
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Notify,
    task::JoinSet,
};
use tracing::instrument;

pub mod wg;
use wg::Peer;

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
    pub peer: wg::Peer,
    pub iface: iface::Interface,
    pub socket_set: Arc<Mutex<SocketSet<'static>>>,
    pub resolver: TokioAsyncResolver,
    pub timeout: Duration,
    pub user_pass: Option<UserPass>,
    update_notify: Arc<Notify>,
    next_ephemeral_port: u16,
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

        let mut peer = Peer::new(tunn, endpoint_addr, peer_conn);

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut peer, Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(iface_addr), 32))
                .unwrap();
        });

        Ok(Self {
            listener,
            peer,
            iface,
            socket_set: Arc::new(Mutex::new(SocketSet::new(Vec::new()))),
            resolver,
            timeout,
            user_pass,
            update_notify: Arc::new(Notify::new()),
            next_ephemeral_port: 1,
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

        let mut poll_next = self.poll_iface();

        let mut update_timers_next = pin!(tokio::time::sleep(Duration::ZERO));

        let mut initial_connections: JoinSet<
            Result<(SocketAddr, SocketHandle, Connection<Piping>), Error>,
        > = JoinSet::new();
        let mut piping: JoinSet<Result<(), Error>> = JoinSet::new();

        loop {
            tokio::select! {
                biased;

                res = self.peer.poll_device(update_timers_next.as_mut()) => {
                    if let Err(e) = res {
                        tracing::warn!(?e, "error in peer device polling");
                    }
                }

                Ok((stream, client_addr)) = self.listener.accept() => {
                    initial_connections.spawn(Box::pin(self.new_conn(
                        stream,
                        client_addr,
                    )));
                }

                Some(conn) = initial_connections.join_next() => {
                    match conn? {
                        Ok((addr, handle, conn)) => {
                            piping.spawn(Box::pin(self.pipe(
                                 addr, handle, conn
                            )));
                        }
                        Err(e) => tracing::warn!(?e, "error in authorized connection"),
                    }
                }

                Some(conn) = piping.join_next() => {
                    if let Err(e) = conn? {
                        tracing::warn!(?e, "error in piping connection");
                    }
                }

                () = poll_next.as_mut() => {
                    poll_next = self.poll_iface();
                }
            }
        }
    }

    fn new_conn(
        &mut self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> impl Future<Output = Result<(SocketAddr, SocketHandle, Connection<Piping>), Error>> {
        tracing::info!(?client_addr, "new connection");

        let socket = tcp::Socket::new(
            SocketBuffer::new(vec![0; 8 * 1024]),
            SocketBuffer::new(vec![0; 8 * 1024]),
        );

        let socket_handle = self.socket_set.lock().unwrap().add(socket);

        let resolver = self.resolver.clone();
        let timeout = self.timeout;
        let user_pass = self.user_pass.clone();
        async move {
            Connection::new(stream, client_addr, resolver, timeout, user_pass)
                .init_conn()
                .await?
                .handle_request()
                .await
                .map(|(addr, conn)| (addr, socket_handle, conn))
        }
    }
    fn pipe(
        &mut self,
        addr: SocketAddr,
        socket_handle: SocketHandle,
        pipe: Connection<Piping>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        tracing::info!(?addr, "connection authorized");

        self.socket_set
            .lock()
            .unwrap()
            .get_mut::<tcp::Socket>(socket_handle)
            .connect(
                self.iface.context(),
                (IpAddress::from(addr.ip()), addr.port()),
                self.next_ephemeral_port,
            )
            .unwrap();
        self.next_ephemeral_port += 1;
        self.update_notify.notify_one();

        Self::pipe_inner(
            self.socket_set.clone(),
            socket_handle,
            self.update_notify.clone(),
            pipe,
        )
    }

    #[instrument(name = "pipe", skip(socket_set, socket_handle, update_notify, pipe))]
    async fn pipe_inner(
        socket_set: Arc<Mutex<SocketSet<'static>>>,
        socket_handle: SocketHandle,
        update_notify: Arc<Notify>,
        mut pipe: Connection<Piping>,
    ) -> Result<(), Error> {
        let mut sock = AsyncSocket {
            socket_set: socket_set.clone(),
            socket_handle,
            update_notify,
        };

        sock.valid_state().await;
        tokio::io::copy_bidirectional(&mut sock, &mut pipe.stream).await?;

        Ok(())
    }

    #[instrument(name = "poll_iface", skip(self))]
    fn poll_iface(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let std_now = std::time::Instant::now();
        let smoltcp_now = smoltcp::time::Instant::from(std_now);
        let tokio_now = tokio::time::Instant::from_std(std_now);

        let (delay, processed) = {
            let mut socket_set = self.socket_set.lock().unwrap();

            let processed = self
                .iface
                .poll(smoltcp_now, &mut self.peer, &mut socket_set);

            let delay = self.iface.poll_delay(smoltcp_now, &socket_set);

            (delay, processed)
        };

        let micros = delay.map_or(0, |d| d.total_micros().saturating_sub(50));
        if micros == 0 {
            tracing::warn!("waiting for device for next poll");

            let device_notify = self.peer.notify.clone();
            let conn_notify = self.update_notify.clone();
            Box::pin(async move {
                tokio::select! {
                    () = device_notify.notified() => {}
                    () = conn_notify.notified() => {}
                }
            })
        } else {
            let wait_dur = Duration::from_micros(micros);
            let next_wake = tokio_now + wait_dur;
            tracing::warn!(next_wake_ms = wait_dur.as_millis(), "polling iface");

            let device_notify = self.peer.notify.clone();
            let conn_notify = self.update_notify.clone();
            Box::pin(async move {
                tokio::select! {
                    () = tokio::time::sleep_until(next_wake) => {}
                    () = device_notify.notified() => {}
                    () = conn_notify.notified() => {}
                }
            })
        }
    }
}

pub struct AsyncSocket {
    pub socket_set: Arc<Mutex<SocketSet<'static>>>,
    pub socket_handle: SocketHandle,
    pub update_notify: Arc<Notify>,
}
impl AsyncSocket {
    pub fn valid_state(&self) -> impl Future<Output = ()> + Send {
        let socket_set = self.socket_set.clone();
        let socket_handle = self.socket_handle;
        let update_notify = self.update_notify.clone();

        poll_fn(move |cx| {
            let mut socket_set = socket_set.lock().unwrap();
            let socket = socket_set.get_mut::<tcp::Socket>(socket_handle);

            socket.register_send_waker(cx.waker());
            socket.register_recv_waker(cx.waker());

            if socket.state() == tcp::State::Established {
                Poll::Ready(())
            } else {
                update_notify.notify_one();
                Poll::Pending
            }
        })
    }
}
impl AsyncRead for AsyncSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut socket_set = self.socket_set.lock().unwrap();
        let socket = socket_set.get_mut::<tcp::Socket>(self.socket_handle);

        socket.register_recv_waker(cx.waker());

        match socket.recv_slice(buf.initialize_unfilled()) {
            Ok(0) => Poll::Pending,
            Ok(ready) => {
                buf.advance(ready);
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Ready(Ok(())),
        }
    }
}
impl AsyncWrite for AsyncSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut socket_set = self.socket_set.lock().unwrap();
        let socket = socket_set.get_mut::<tcp::Socket>(self.socket_handle);

        socket.register_send_waker(cx.waker());

        match socket.send_slice(buf) {
            Ok(0) => Poll::Pending,
            Ok(ready) => {
                self.update_notify.notify_one();
                Poll::Ready(Ok(ready))
            }
            Err(_) => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // TODO: flush?
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut socket_set = self.socket_set.lock().unwrap();
        let socket = socket_set.get_mut::<tcp::Socket>(self.socket_handle);
        tracing::warn!("shutting down socket");
        socket.close();

        self.update_notify.notify_one();

        Poll::Ready(Ok(()))
    }
}
