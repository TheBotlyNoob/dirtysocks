#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use boringtun::noise::Tunn;
use futures_util::{
    future::{Either, JoinAll},
    stream::FuturesUnordered,
    StreamExt,
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
    f64::consts::E,
    future::{poll_fn, Future},
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    pin::{pin, Pin},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration as StdDuration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
            iface: Some(IfaceHandler {
                socket_rx,
                sockets_tx: HashMap::new(),
                iface,
                socket_set: SocketSet::new(Vec::new()),
                peer,
                next_ephemeral_port: NonZeroU16::new(1).unwrap(),
                send_queue: HashMap::new(),
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

        let mut iface = self.iface.take().unwrap();
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

    async fn handle_conn(sender: Sender<ToWgMsg>, conn: Connection<Initial>) -> Result<(), Error> {
        let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel(128);

        let (socket_addr, mut pipe) = conn.init_conn().await?.handle_request().await?;

        sender
            .send(ToWgMsg::Connect(socket_addr, socket_tx))
            .await
            .unwrap();

        let FromWgMsg::Connect(handle) = socket_rx.recv().await.unwrap() else {
            unreachable!();
        };

        let mut recv_buf = [0; 8 * 1024];

        loop {
            tokio::select! {
                Some(msg) = socket_rx.recv() => {
                    match msg {
                        FromWgMsg::Data(data) => pipe.stream.write_all(&data).await?,
                        FromWgMsg::Close => pipe.stream.shutdown().await?,
                        FromWgMsg::Connect(_) => unreachable!(),
                    }
                }
                read = pipe.stream.read(&mut recv_buf) => {
                    let read = read?;
                    sender.send(if read == 0 {
                        ToWgMsg::Close(handle)
                    } else {
                        ToWgMsg::Data(handle, recv_buf[..read].to_vec().into_boxed_slice())
                    }).await.unwrap();

                    if read == 0 {
                        pipe.stream.shutdown().await?;
                        break;
                    }
                }
                else => {
                    sender.send(ToWgMsg::Close(handle)).await.unwrap();
                    pipe.stream.shutdown().await?;
                }
            }
        }

        Ok(())
    }
}

pub struct IfaceHandler {
    socket_rx: Receiver<ToWgMsg>,
    sockets_tx: HashMap<SocketHandle, Sender<FromWgMsg>>,
    send_queue: HashMap<SocketHandle, Vec<Box<[u8]>>>,
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

        loop {
            if needs_poll || !self.send_queue.is_empty() {
                self.poll_iface().await;
                needs_poll = false;
            }

            tokio::select! {
                Some(msg) = self.socket_rx.recv() => {
                    self.handle_msg(msg).await;
                    needs_poll = true;
                },

                _ = self.peer.poll_device(last_device_poll.as_mut()) => {
                    needs_poll |= !self.peer.rx_queue.is_empty();
                },

                _ = Self::wait_for_poll_iface(self.last_iface_poll, self.iface_poll_delay) => {
                    needs_poll = true;
                },
            }
        }
    }

    async fn poll_iface(&mut self) {
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
            for handle in self.poll_sockets().await.into_iter().flatten() {
                tracing::info!(handle = ?handle, "socket closed");
                self.sockets_tx.remove(&handle);
                self.send_queue.remove(&handle);
                self.socket_set.remove(handle);
            }
        }
    }

    fn poll_sockets(&mut self) -> JoinAll<impl Future<Output = Option<SocketHandle>>> {
        tracing::info!("polling sockets");

        futures_util::future::join_all(self.socket_set.iter_mut().map(|(handle, socket)| {
            let socket = tcp::Socket::downcast_mut(socket).unwrap();

            if socket.can_recv() {
                tracing::info!(handle = ?handle, "socket can recv");

                let sender = self.sockets_tx.get_mut(&handle).unwrap();

                let mut buf = [0; 8 * 1024];
                let read = socket.recv_slice(&mut buf).unwrap();

                tracing::info!(handle = ?handle, read = read, "read data from socket");

                let data = buf[..read].to_vec().into_boxed_slice();

                let sender = sender.clone();
                Either::Left(Either::Left(async move {
                    sender.send(FromWgMsg::Data(data)).await.unwrap();
                    None
                }))
            } else if socket.can_send() {
                tracing::info!(handle = ?handle, "socket can send");

                if let Some(queue) = self.send_queue.get_mut(&handle) {
                    tracing::info!(handle = ?handle, queue_len = queue.len(), "sending queued data");

                    while let Some(data) = queue.pop() {
                        tracing::info!(handle = ?handle, data_len = data.len(), "sending data");

                        let sent = socket.send_slice(&data).unwrap();

                        if sent < data.len() {
                            queue.push(data[sent..].to_vec().into_boxed_slice());
                            break;
                        } else if !socket.can_send() {
                            break;
                        }
                    }
                }
                Either::Right(std::future::ready(None))
            } else if matches!(socket.state(), tcp::State::Closed | tcp::State::CloseWait) {
                tracing::info!(handle = ?handle, "socket is closed");

                let sender = self.sockets_tx.get_mut(&handle).unwrap().clone();

                Either::Left(Either::Right(async move {
                    // the socket might be closed from the other side
                    // so the sender might not be able to send any more
                    let _ = sender.send(FromWgMsg::Close).await;
                    Some(handle)
                }))
            } else {
                Either::Right(std::future::ready(None))
            }
        }))
    }

    async fn handle_msg(&mut self, msg: ToWgMsg) {
        match msg {
            ToWgMsg::Connect(addr, sender) => {
                tracing::info!(?addr, "connecting to address");

                let mut socket = tcp::Socket::new(
                    SocketBuffer::new(vec![0; 8 * 1024]),
                    SocketBuffer::new(vec![0; 8 * 1024]),
                );

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

                self.sockets_tx.insert(handle, sender.clone());
            }
            ToWgMsg::Data(handle, data) => {
                let socket = self.socket_set.get_mut::<tcp::Socket>(handle);

                if socket.can_send() {
                    tracing::info!(handle = ?handle, data_len = data.len(), "socket can send");

                    socket.send_slice(&data).unwrap();
                } else {
                    tracing::info!(handle = ?handle, "socket can't send, queueing data");

                    self.send_queue.entry(handle).or_default().push(data);
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
                tracing::warn!(next_wake_ms = wait_dur.as_millis(), elapsed = ?std::time::Instant::now().saturating_duration_since(now), "polling iface");

                Either::Right(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    next_wake,
                )))
            }
        }
    }
}
