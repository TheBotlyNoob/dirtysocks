#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_pub_crate,
    clippy::module_name_repetitions
)]

use boringtun::noise::Tunn;
use futures_util::{
    future::{join_all, Either},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use handler::{Connection, Initial};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use smoltcp::{
    config::IFACE_MAX_ADDR_COUNT,
    iface::{self, Config, SocketHandle, SocketSet},
    socket::{
        tcp::{self, SocketBuffer},
        AnySocket,
    },
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    num::NonZeroU16,
    pin::pin,
    time::{Duration as StdDuration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc::{Receiver, Sender},
    time::Instant as TokioInstant,
};
use tracing::instrument;

pub mod wg;
use wg::Peer;

pub mod handler;

pub const MAX_PACKET_SIZE: usize = 65535;

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
    #[error("failed to message worker thread")]
    SendError,
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
    Data(SocketHandle, Box<[u8]>),
    Close(SocketHandle),
}

#[derive(Debug)]
enum FromWgMsg {
    Connect(SocketHandle),
    Data(Box<[u8]>),
    Close,
}

pub struct ServerOptions {
    pub listener: TcpListener,
    pub tunn: Tunn,
    /// The address of the wireguard server.
    pub endpoint_addr: SocketAddr,
    pub max_transmission_unit: usize,
    pub resolver: TokioAsyncResolver,
    pub timeout: StdDuration,
    pub user_pass: Option<UserPass>,
    pub iface_addrs: heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
}
impl ServerOptions {
    pub fn new(
        listener: TcpListener,
        endpoint_addr: SocketAddr,
        tunn: Tunn,
        iface_addrs: heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    ) -> Self {
        Self {
            listener,
            endpoint_addr,
            tunn,
            iface_addrs,
            resolver: TokioAsyncResolver::tokio(
                ResolverConfig::cloudflare(),
                ResolverOpts::default(),
            ),
            timeout: StdDuration::from_secs(30),
            user_pass: None,
            max_transmission_unit: 1280,
        }
    }
}

/// A socks5 server implementation, sending data to a single `WireGuard` peer.
pub struct Server {
    pub listener: TcpListener,
    pub iface: Option<IfaceHandler>,
    pub resolver: TokioAsyncResolver,
    pub timeout: StdDuration,
    pub user_pass: Option<UserPass>,
    pub next_ephemeral_port: u16,

    socket_tx: Sender<ToWgMsg>,
}

// TODO: reuse sockets
impl Server {
    pub async fn listen(opts: ServerOptions) -> Result<Infallible, Error> {
        let peer_conn = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        peer_conn.connect(opts.endpoint_addr).await?;

        let mut peer = Peer::new(
            opts.tunn,
            opts.endpoint_addr,
            peer_conn,
            opts.max_transmission_unit,
        );

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut peer, SmolInstant::now());

        iface.update_ip_addrs(|ip_addrs| *ip_addrs = opts.iface_addrs);

        let (socket_tx, socket_rx) = tokio::sync::mpsc::channel(128);

        let this = Self {
            listener: opts.listener,
            iface: Some(IfaceHandler {
                socket_rx,
                iface,
                socket_set: SocketSet::new(Vec::new()),
                peer,
                next_ephemeral_port: NonZeroU16::new(1).unwrap(),
                sockets_ctx: HashMap::new(),
                last_iface_poll: StdInstant::now(),
                iface_poll_delay: None,
            }),
            socket_tx,
            resolver: opts.resolver,
            timeout: opts.timeout,
            user_pass: opts.user_pass,
            next_ephemeral_port: 1,
        };

        this.listen_().await
    }

    async fn listen_(mut self) -> Result<Infallible, Error> {
        tracing::info!("SOCKS5 server started");
        if self.user_pass.is_some() {
            tracing::info!("using username/password authentication");
        } else {
            tracing::info!("no authentication required");
        }

        let mut piping = FuturesUnordered::new();

        let iface = self.iface.take().unwrap();
        tokio::spawn(iface.handle_iface());

        loop {
            tokio::select! {
                biased;

                Ok((stream, client_addr)) = self.listener.accept() => {
                    piping.push(Self::handle_conn(
                        self.socket_tx.clone(),
                        Connection::new(
                            stream,
                            client_addr,
                            self.resolver.clone(),
                            self.timeout,
                            self.user_pass.clone()
                        )
                    ));
                }

                Some(conn) = piping.next() => {
                    if let Err(e) = conn {
                        tracing::warn!(?e, "error in piping connection");
                    }
                }
            }
        }
    }

    #[instrument(skip(sender, conn))]
    async fn handle_conn(sender: Sender<ToWgMsg>, conn: Connection<Initial>) -> Result<(), Error> {
        let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel(128);

        let (socket_addr, mut pipe) = conn.init_conn().await?.handle_request().await?;

        tracing::trace!(?socket_addr, "connected to remote");

        if sender
            .send(ToWgMsg::Connect(socket_addr, socket_tx))
            .await
            .is_err()
        {
            tracing::error!("error sending connect message to iface");
            return Err(Error::SendError);
        };

        match socket_rx.recv().await {
            Some(FromWgMsg::Connect(handle)) => {
                tracing::trace!(handle = ?handle, "allocated handle");
            }
            Some(FromWgMsg::Close) => {
                tracing::warn!("spurious close message");
                return Ok(());
            }
            _ => {
                return Err(Error::SendError);
            }
        }

        let Some(FromWgMsg::Connect(handle)) = socket_rx.recv().await else {
            return Err(Error::SendError);
        };

        tracing::trace!(handle = ?handle, "allocated handle");

        let mut recvd_len = 0;
        let mut flush_next = None;

        let mut chunks = VecDeque::with_capacity(64);

        loop {
            tokio::select! {
                Some(msg) = socket_rx.recv() => {
                    match msg {
                        FromWgMsg::Data(data) => {
                            tracing::trace!(data_len = data.len(), "sending data to remote");

                            recvd_len += data.len();
                            chunks.push_front(data);

                            if recvd_len >= 32 * 1024 {
                                tracing::trace!("flushing buf");

                                while let Some(chunk) = chunks.pop_back() {
                                    pipe.stream.write_all(&chunk).await?;
                                }
                                recvd_len = 0;
                                flush_next = None;
                            } else {
                                flush_next = Some(TokioInstant::now() + StdDuration::from_millis(100));
                            }
                        },
                        FromWgMsg::Close => break,
                        FromWgMsg::Connect(_) => {
                            tracing::warn!("spurious connect message");
                        },
                    }
                }
                read = pipe.stream.read(&mut pipe.buf) => {
                    let Ok(read) = read else {
                        tracing::warn!("error reading from stream");
                        break;
                    };

                    tracing::trace!(read, "read data from stream");

                    if read == 0 {
                        tracing::info!("stream closed");
                        break;
                    }

                    if sender.send(
                        ToWgMsg::Data(
                            handle,
                            pipe.buf[..read].to_vec().into_boxed_slice()
                        )
                    )
                    .await
                    .is_err() {
                        tracing::error!("error sending data to iface");
                        break;
                    };
                }
                () = flush_next.map_or_else(
                    || Either::Left(std::future::pending()),
                    |next| Either::Right(tokio::time::sleep_until(next))
                ) => {
                    tracing::warn!("flushing buffer");

                    while let Some(chunk) = chunks.pop_back() {
                        pipe.stream.write_all(&chunk).await?;
                    }
                    recvd_len = 0;
                    flush_next = None;
                }
            }
        }

        let _ = sender.send(ToWgMsg::Close(handle)).await;
        pipe.stream.shutdown().await?;

        Ok(())
    }
}

struct SocketCtx {
    sender: Sender<FromWgMsg>,
    send_queue: Vec<Box<[u8]>>,
}

pub struct IfaceHandler {
    socket_rx: Receiver<ToWgMsg>,
    sockets_ctx: HashMap<SocketHandle, SocketCtx>,
    iface: iface::Interface,
    peer: wg::Peer,
    socket_set: SocketSet<'static>,
    last_iface_poll: StdInstant,
    iface_poll_delay: Option<SmolDuration>,
    next_ephemeral_port: NonZeroU16,
}

impl IfaceHandler {
    pub async fn handle_iface(mut self) {
        let mut needs_poll = false;

        let mut last_device_poll = pin!(tokio::time::sleep(StdDuration::ZERO));
        let mut device_buf = Box::new([0; MAX_PACKET_SIZE]);

        let mut msg_queue = Vec::with_capacity(self.socket_rx.max_capacity());

        loop {
            while needs_poll || !self.peer.rx_queue.is_empty() {
                self.poll_iface().await;
                needs_poll = false;
                self.peer.should_poll = false;
            }

            tokio::select! {
                n = self.socket_rx.recv_many(&mut msg_queue, 128) => {
                    for msg in msg_queue.drain(..n) {
                        self.handle_msg(msg).await;
                    }
                    needs_poll = true;
                },

                e = self.peer.poll_device(last_device_poll.as_mut(), &mut *device_buf) => {
                    if let Err(e) = e {
                        tracing::warn!(?e, "error polling device");
                    }
                    needs_poll |= self.peer.should_poll;
                },

                () = Self::wait_for_poll_iface(self.last_iface_poll, self.iface_poll_delay) => {
                    needs_poll = true;
                },
            }
        }
    }

    async fn poll_iface(&mut self) {
        tracing::info!("polling");

        self.last_iface_poll = StdInstant::now();
        let smoltcp_now = SmolInstant::from(self.last_iface_poll);

        let (delay, processed) = {
            let processed = self
                .iface
                .poll(smoltcp_now, &mut self.peer, &mut self.socket_set);

            let delay = self.iface.poll_delay(smoltcp_now, &self.socket_set);

            (delay, processed)
        };

        self.iface_poll_delay = delay;

        if processed {
            self.poll_sockets().await;
        }
    }

    async fn poll_sockets(&mut self) {
        tracing::trace!("polling sockets");

        let joined = join_all(self.socket_set.iter_mut().map(|(handle, socket)| {
            Self::poll_socket(
                handle,
                tcp::Socket::downcast_mut(socket).unwrap(),
                self.sockets_ctx.get_mut(&handle).unwrap(),
            )
        }));

        for handle in joined.await.into_iter().flatten() {
            tracing::trace!(handle = ?handle, "socket closed");
            self.sockets_ctx.remove(&handle);
            self.socket_set.remove(handle);
        }
    }

    fn poll_socket(
        handle: SocketHandle,
        socket: &mut tcp::Socket<'static>,
        ctx: &mut SocketCtx,
    ) -> impl Future<Output = Option<SocketHandle>> {
        let mut messages = [None, None];

        if socket.can_recv() {
            tracing::trace!(handle = ?handle,  queue_size = socket.recv_queue(), "socket can recv");
            if let Err(e) = socket.recv(|buf| {
                tracing::trace!(handle = ?handle, read = buf.len(), "read data from socket");
                let data = buf.to_vec().into_boxed_slice();

                messages[0] = Some(FromWgMsg::Data(data));

                (buf.len(), ())
            }) {
                tracing::warn!(?e, "error reading from socket");
            };
        }

        if socket.can_send() {
            tracing::trace!(handle = ?handle, "socket can send");

            tracing::trace!(handle = ?handle, queue_len = ctx.send_queue.len(), "sending queued data");

            while let Some(data) = ctx.send_queue.pop() {
                tracing::trace!(handle = ?handle, data_len = data.len(), "sending data");

                let sent = socket.send_slice(&data).unwrap_or(0);

                if sent < data.len() {
                    ctx.send_queue
                        .push(data[sent..].to_vec().into_boxed_slice());
                    break;
                } else if !socket.can_send() {
                    break;
                }
            }
        }

        if matches!(socket.state(), tcp::State::Closed | tcp::State::CloseWait) {
            tracing::trace!(handle = ?handle, "socket is closed");

            messages[1] = Some(FromWgMsg::Close);
        }

        join_all(messages.into_iter().flatten().map(move |msg| {
            let sender = ctx.sender.clone();
            async move {
                let mut close = matches!(msg, FromWgMsg::Close);
                if let Err(e) = sender.send(msg).await {
                    tracing::warn!(?e, "error sending message to socket");
                    close = true;
                }

                if close {
                    Some(handle)
                } else {
                    None
                }
            }
        }))
        .map(|to_close| to_close.into_iter().find_map(|h| h))
    }

    async fn handle_msg(&mut self, msg: ToWgMsg) {
        match msg {
            ToWgMsg::Connect(addr, sender) => {
                tracing::trace!(?addr, "connecting to address");

                let mut socket = tcp::Socket::new(
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                );

                socket.set_nagle_enabled(false);
                socket.set_keep_alive(Some(SmolDuration::from_secs(30)));

                if let Err(e) = socket.connect(
                    self.iface.context(),
                    (IpAddress::from(addr.ip()), addr.port()),
                    self.next_ephemeral_port.get(),
                ) {
                    tracing::warn!(?e, "error connecting to address");

                    return;
                }

                self.next_ephemeral_port = self.next_ephemeral_port.saturating_add(1);

                let handle = self.socket_set.add(socket);

                if sender.send(FromWgMsg::Connect(handle)).await.is_err() {
                    tracing::error!("error sending connect message to socket");
                    self.socket_set.get_mut::<tcp::Socket>(handle).abort();
                }

                self.sockets_ctx.insert(
                    handle,
                    SocketCtx {
                        sender,
                        send_queue: Vec::new(),
                    },
                );
            }
            ToWgMsg::Data(handle, data) => {
                if let Some(ctx) = self.sockets_ctx.get_mut(&handle) {
                    let socket = self.socket_set.get_mut::<tcp::Socket>(handle);

                    if socket.can_send() {
                        tracing::trace!(handle = ?handle, data_len = data.len(), "socket can send");

                        let sent = socket.send_slice(&data).unwrap_or(0);

                        if sent < data.len() {
                            tracing::trace!(handle = ?handle, data_len = data.len(), sent, "socket can't send all data, queueing");

                            ctx.send_queue
                                .push(data[sent..].to_vec().into_boxed_slice());
                        }
                    } else {
                        tracing::trace!(handle = ?handle, "socket can't send, queueing data");

                        ctx.send_queue.push(data);
                    }
                } else {
                    tracing::warn!(handle = ?handle, "socket not found");
                }
            }
            ToWgMsg::Close(handle) => {
                tracing::trace!(handle = ?handle, "closing socket");

                if self.sockets_ctx.contains_key(&handle) {
                    self.socket_set.get_mut::<tcp::Socket>(handle).abort();
                }
            }
        }
    }

    fn wait_for_poll_iface(
        now: std::time::Instant,
        delay: Option<SmolDuration>,
    ) -> impl Future<Output = ()> {
        match delay {
            None => {
                tracing::trace!("waiting for device for next poll");

                Either::Left(Either::Left(std::future::pending()))
            }
            Some(SmolDuration::ZERO) => Either::Left(Either::Right(std::future::ready(()))),
            Some(delay) => {
                let wait_dur = StdDuration::from_micros(delay.total_micros());
                let next_wake = now + wait_dur;
                tracing::trace!(next_wake_ms = wait_dur.as_millis(), elapsed = ?std::time::Instant::now().saturating_duration_since(now), "will poll iface");

                Either::Right(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    next_wake,
                )))
            }
        }
    }
}
