#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_pub_crate,
    clippy::module_name_repetitions
)]

use boringtun::noise::Tunn;
use futures_util::{
    future::{join_all, Either, JoinAll},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use handler::{Connection, Initial};
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
    future::Future,
    net::{IpAddr, SocketAddr},
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

        tracing::info!(?socket_addr, "connected to remote");

        sender
            .send(ToWgMsg::Connect(socket_addr, socket_tx))
            .await
            .unwrap();

        let FromWgMsg::Connect(handle) = socket_rx.recv().await.unwrap() else {
            unreachable!();
        };

        tracing::info!(handle = ?handle, "allocated handle");

        let mut recvd_len = 0;
        let mut flush_next = None;

        loop {
            tokio::select! {
                Some(msg) = socket_rx.recv() => {
                    match msg {
                        FromWgMsg::Data(data) => {
                            tracing::info!(data_len = data.len(), "sending data to remote");

                            pipe.buf[recvd_len..recvd_len + data.len()].copy_from_slice(&data);
                            recvd_len += data.len();

                            if recvd_len >= 8 * 1024 {
                                tracing::warn!("buffer full, flushing");

                                pipe.stream.flush().await?;
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
                read = pipe.stream.read(&mut pipe.buf[recvd_len..]) => {
                    let Ok(read) = read else {
                        tracing::warn!("error reading from stream");
                        break;
                    };

                    tracing::info!(read, "read data from stream");

                    if read == 0 {
                        tracing::info!("stream closed");
                        break;
                    }

                    sender.send(
                        ToWgMsg::Data(
                            handle,
                            pipe.buf[recvd_len..recvd_len + read]
                                .to_vec()
                                .into_boxed_slice()
                        )
                    )
                    .await
                    .unwrap();
                }
                () = flush_next.map_or_else(
                    || Either::Left(std::future::pending()),
                    |next| Either::Right(tokio::time::sleep_until(next))
                ) => {
                    tracing::warn!("flushing buffer");

                    pipe.stream.write_all(&pipe.buf[..recvd_len]).await?;
                    pipe.stream.flush().await?;
                    recvd_len = 0;
                    flush_next = None;
                }
            }
        }

        sender.send(ToWgMsg::Close(handle)).await.unwrap();
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

        let mut pre_process_sockets = false;

        let mut last_device_poll = pin!(tokio::time::sleep(StdDuration::ZERO));
        let mut device_buf = Box::new([0; MAX_PACKET_SIZE]);

        loop {
            if needs_poll {
                tracing::info!("needs a poll");
                self.poll_iface(pre_process_sockets).await;
                needs_poll = false;
                pre_process_sockets = false;
            }

            tokio::select! {
                Some(msg) = self.socket_rx.recv() => {
                    self.handle_msg(msg).await;
                    needs_poll = true;
                    pre_process_sockets = true;
                },

                e = self.peer.poll_device(last_device_poll.as_mut(), &mut *device_buf) => {
                    if let Err(e) = e {
                        tracing::warn!(?e, "error polling device");
                    }
                    needs_poll |= !self.peer.rx_queue.is_empty();
                    needs_poll = true;
                },

                () = Self::wait_for_poll_iface(self.last_iface_poll, self.iface_poll_delay) => {
                    needs_poll = true;
                },
            }
        }
    }

    async fn poll_iface(&mut self, pre_process_sockets: bool) {
        if pre_process_sockets {
            self.poll_sockets().await;
        }

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
        tracing::info!("polling sockets");

        let joined = join_all(self.socket_set.iter_mut().map(|(handle, socket)| {
            Self::poll_socket(
                handle,
                tcp::Socket::downcast_mut(socket).unwrap(),
                self.sockets_ctx.get_mut(&handle).unwrap(),
            )
        }));

        for handle in joined.await.into_iter().flatten() {
            tracing::info!(handle = ?handle, "socket closed");
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
            tracing::info!(handle = ?handle,  queue_size = socket.recv_queue(), "socket can recv");
            socket
                .recv(|buf| {
                    tracing::info!(handle = ?handle, read = buf.len(), "read data from socket");
                    let data = buf.to_vec().into_boxed_slice();

                    messages[0] = Some(FromWgMsg::Data(data));

                    (buf.len(), ())
                })
                .unwrap();
        }

        if socket.can_send() {
            tracing::info!(handle = ?handle, "socket can send");

            tracing::info!(handle = ?handle, queue_len = ctx.send_queue.len(), "sending queued data");

            while let Some(data) = ctx.send_queue.pop() {
                tracing::info!(handle = ?handle, data_len = data.len(), "sending data");

                let sent = socket.send_slice(&data).unwrap();

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
            tracing::info!(handle = ?handle, "socket is closed");

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
                tracing::info!(?addr, "connecting to address");

                let mut socket = tcp::Socket::new(
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                );

                socket.set_nagle_enabled(false);
                socket.set_keep_alive(Some(SmolDuration::from_secs(30)));

                socket
                    .connect(
                        self.iface.context(),
                        (IpAddress::from(addr.ip()), addr.port()),
                        self.next_ephemeral_port.get(),
                    )
                    .unwrap();

                self.next_ephemeral_port = self.next_ephemeral_port.saturating_add(1);

                let handle = self.socket_set.add(socket);

                sender.send(FromWgMsg::Connect(handle)).await.unwrap();

                self.sockets_ctx.insert(
                    handle,
                    SocketCtx {
                        sender,
                        send_queue: Vec::new(),
                    },
                );
            }
            ToWgMsg::Data(handle, data) => {
                let socket = self.socket_set.get_mut::<tcp::Socket>(handle);

                if socket.can_send() {
                    tracing::info!(handle = ?handle, data_len = data.len(), "socket can send");

                    socket.send_slice(&data).unwrap();
                } else {
                    tracing::info!(handle = ?handle, "socket can't send, queueing data");

                    self.sockets_ctx
                        .get_mut(&handle)
                        .unwrap()
                        .send_queue
                        .push(data);
                }
            }
            ToWgMsg::Close(handle) => {
                tracing::info!(handle = ?handle, "closing socket");

                self.socket_set.get_mut::<tcp::Socket>(handle).abort();
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
                tracing::warn!(next_wake_ms = wait_dur.as_millis(), elapsed = ?std::time::Instant::now().saturating_duration_since(now), "will poll iface");

                Either::Right(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    next_wake,
                )))
            }
        }
    }
}
