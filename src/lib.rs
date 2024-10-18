#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use futures_util::{future::Either, stream::FuturesUnordered, StreamExt};
use handler::{Connection, Piping};
use hickory_resolver::TokioAsyncResolver;
use smoltcp::{
    iface::{self, Config, SocketHandle, SocketSet},
    socket::{
        tcp::{self, SocketBuffer},
        AnySocket,
    },
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::HashMap,
    convert::Infallible,
    future::{poll_fn, Future},
    net::{IpAddr, SocketAddr},
    pin::{pin, Pin},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration as StdDuration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        mpsc::{Receiver, Sender},
        Notify,
    },
    time::Instant as TokioInstant,
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

#[derive(Debug)]
enum ToWgMsg {
    Connect(SocketAddr, Sender<FromWgMsg>),
    Data(SocketHandle, Vec<u8>),
    Close(SocketHandle),
}

#[derive(Debug)]
enum FromWgMsg {
    Connect(SocketHandle),
    Data(Vec<u8>),
    Close,
}

/// A socks5 server implementation, sending data to a single `WireGuard` peer.
pub struct Server {
    pub listener: TcpListener,
    pub poll_iface: Option<PollIface>,
    pub socket_tx: Sender<ToWgMsg>,
    pub resolver: TokioAsyncResolver,
    pub timeout: StdDuration,
    pub user_pass: Option<UserPass>,
    pub next_ephemeral_port: u16,
}

// TODO: reuse sockets
impl Server {
    // TODO: use builder for this
    pub async fn new(
        listener: TcpListener,
        tunn: Tunn,
        endpoint_addr: SocketAddr,
        resolver: TokioAsyncResolver,
        timeout: StdDuration,
        user_pass: Option<UserPass>,
        iface_addr: IpAddr,
    ) -> Result<Self, Error> {
        let peer_conn = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        peer_conn.connect(endpoint_addr).await?;

        let mut peer = Peer::new(tunn, endpoint_addr, peer_conn);

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut peer, SmolInstant::now());

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(iface_addr), 32))
                .unwrap();
        });

        let (socket_tx, socket_rx) = tokio::sync::mpsc::channel(128);

        Ok(Self {
            listener,
            poll_iface: Some(PollIface {
                socket_rx,
                sockets_tx: HashMap::new(),
                iface,
                socket_set: SocketSet::new(Vec::new()),
                peer,
            }),
            socket_tx,
            resolver,
            timeout,
            user_pass,
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

        let mut poll_now = std::time::Instant::now();
        let mut poll_next = self.poll_iface(poll_now);

        let mut update_timers_next = pin!(tokio::time::sleep(StdDuration::ZERO));

        let mut initial_connections = FuturesUnordered::new();
        let mut piping = FuturesUnordered::new();

        let poll_iface = self.poll_iface.take().unwrap();
        tokio::spawn(poll_iface.poll_iface());

        let peer_notify = self.peer.notify.clone();

        loop {
            tokio::select! {
                biased;

                res = self.peer.poll_device(update_timers_next.as_mut()) => {
                    if let Err(e) = res {
                        tracing::warn!(?e, "error in peer device polling");
                    }
                }

                Ok((stream, client_addr)) = self.listener.accept() => {
                    initial_connections.push(self.new_conn(
                        stream,
                        client_addr,
                    ));
                }

                Some(conn) = initial_connections.next() => {
                    match conn {
                        Ok((addr, handle, conn)) => {
                            piping.push(self.pipe(
                                 addr, handle, conn
                           ));
                        }
                        Err(e) => tracing::warn!(?e, "error in authorized connection"),
                    }
                }

                () = Self::wait_for_poll_iface(peer_notify.clone(), self.new_conn_notify.clone(), poll_now, poll_next) => {
                    poll_now = std::time::Instant::now();
                    poll_next = self.poll_iface(poll_now);
                }

                Some(conn) = piping.next() => {
                    if let Err(e) = conn {
                        tracing::warn!(?e, "error in piping connection");
                    }
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
    ) -> impl Future<Output = Result<(), Error>> {
        tracing::info!(?addr, "connection authorized");

        self.socket_set
            .try_lock()
            .unwrap()
            .get_mut::<tcp::Socket>(socket_handle)
            .connect(
                self.iface.context(),
                (IpAddress::from(addr.ip()), addr.port()),
                self.next_ephemeral_port,
            )
            .unwrap();
        self.next_ephemeral_port += 1;
        self.new_conn_notify.notify_one();

        Self::pipe_inner(
            self.socket_set.clone(),
            socket_handle,
            self.new_conn_notify.clone(),
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
    fn poll_iface(&mut self, now: std::time::Instant) -> Option<SmolDuration> {
        let smoltcp_now = smoltcp::time::Instant::from(now);

        let (delay, processed) = {
            let mut socket_set = self.socket_set.lock().unwrap();

            let processed = self
                .iface
                .poll(smoltcp_now, &mut self.peer, &mut socket_set);

            let delay = self.iface.poll_delay(smoltcp_now, &socket_set);

            (delay, processed)
        };

        delay
    }
}

struct PollIface {
    socket_rx: Receiver<ToWgMsg>,
    sockets_tx: HashMap<SocketHandle, Sender<FromWgMsg>>,
    iface: iface::Interface,
    peer: wg::Peer,
    socket_set: SocketSet<'static>,
    next_ephemeral_port: u16,
}

impl PollIface {
    pub async fn poll_iface(mut self) {
        let mut last_iface_poll = StdInstant::now();
        let mut iface_poll_delay = None;

        let mut did_something = false;

        loop {
            tokio::select! {
                biased;

                Some(msg) = self.socket_rx.recv() => self.handle_msg(msg),

                _ = Self::wait_for_poll_iface(last_iface_poll, iface_poll_delay) => {
                    last_iface_poll = StdInstant::now();
                    let smoltcp_now = SmolInstant::from(last_iface_poll);

                    let (delay, processed) = {
                        let processed = self.iface.poll(smoltcp_now, &mut self.peer, &mut self.socket_set);

                        let delay = self.iface.poll_delay(smoltcp_now, &self.socket_set);

                        (delay, processed)
                    };

                    iface_poll_delay = delay;

                    self.poll_sockets().await;
                }
            }
        }
    }

    async fn poll_sockets(&mut self) {
        futures_util::future::join_all(self.socket_set.iter_mut().map(|(handle, socket)| {
            let socket = tcp::Socket::downcast_mut(socket).unwrap();

            if socket.can_recv() {
                let sender = self.sockets_tx.get_mut(&handle).unwrap();

                let mut buf = [0; 8 * 1024];
                let read = socket.recv_slice(&mut buf).unwrap();

                let data = buf[..read].to_vec();

                let sender = sender.clone();
                Either::Left(async move {
                    sender.send(FromWgMsg::Data(data)).await.unwrap();
                })
            } else {
                Either::Right(async {})
            }
        }))
        .await;
    }

    async fn send_to(&mut self, handle: SocketHandle, msg: FromWgMsg) {
        let sender = self.sockets_tx.get_mut(&handle).unwrap();
        sender.send(msg).await.unwrap();
    }

    fn handle_msg(&mut self, msg: ToWgMsg) {
        match msg {
            ToWgMsg::Connect(addr, sender) => {
                let mut socket = tcp::Socket::new(
                    SocketBuffer::new(vec![0; 8 * 1024]),
                    SocketBuffer::new(vec![0; 8 * 1024]),
                );

                socket
                    .connect(
                        self.iface.context(),
                        (IpAddress::from(addr.ip()), addr.port()),
                        self.next_ephemeral_port,
                    )
                    .unwrap();

                self.next_ephemeral_port += 1;

                let handle = self.socket_set.add(socket);

                self.sockets_tx.insert(handle, sender);
            }
            ToWgMsg::Data(handle, data) => {
                let socket = self.socket_set.get_mut::<tcp::Socket>(handle);

                socket.send_slice(&data).unwrap();
            }
            ToWgMsg::Close(handle) => {
                self.socket_set.get_mut::<tcp::Socket>(handle).close();
            }
        }
    }

    fn wait_for_poll_iface(
        now: std::time::Instant,
        delay: Option<SmolDuration>,
    ) -> impl Future<Output = ()> {
        match delay {
            None => {
                tracing::warn!("waiting for device for next poll");

                Either::Left(Either::Left(std::future::pending()))
            }
            Some(SmolDuration::ZERO) => Either::Left(Either::Right(std::future::ready(()))),
            Some(delay) => {
                let wait_dur = StdDuration::from_micros(delay.total_micros());
                let next_wake = now + wait_dur;
                tracing::warn!(next_wake_ms = wait_dur.as_millis(), elapsed = ?std::time::Instant::now().saturating_duration_since(now), "polling iface");

                Either::Right(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    next_wake,
                )))
            }
        }
    }
}

pub struct AsyncSocket {
    pub socket_set: Arc<Mutex<SocketSet<'static>>>,
    pub socket_handle: SocketHandle,
    pub update_notify: Arc<Notify>,
}
impl AsyncSocket {
    pub fn valid_state(&self) -> impl Future<Output = ()> {
        let socket_set = self.socket_set.clone();
        let socket_handle = self.socket_handle;
        let update_notify = self.update_notify.clone();

        poll_fn(move |cx| {
            tracing::info!("checking for sendable socket state");

            let mut socket_set = socket_set.try_lock().unwrap();
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
        tracing::info!(handle = ?self.socket_handle, "polling socket read");

        let mut socket_set = self.socket_set.try_lock().unwrap();
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
        tracing::info!("polling socket write");

        let mut socket_set = self.socket_set.try_lock().unwrap();
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
        tracing::info!("shutting down socket");

        let mut socket_set = self.socket_set.try_lock().unwrap();
        let socket = socket_set.get_mut::<tcp::Socket>(self.socket_handle);
        tracing::warn!("shutting down socket");
        socket.close();

        self.update_notify.notify_one();

        Poll::Ready(Ok(()))
    }
}
