use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use deadqueue::unlimited::Queue;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    wire::{Ipv4Packet, PrettyPrinter},
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, MutexGuard, PoisonError,
    },
    time::Duration,
};
use tokio::net::UdpSocket;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet parse error: {0}")]
    ParsePacket(#[from] smoltcp::wire::Error),
    #[error("wireguard error: {0:#?}")]
    WireGuard(WireGuardError),
    #[error("mutex poisoned")]
    MutexPoisoned,
}
// thiserror doesn't like WireGuardError for some reason
// so I have to implement From myself
impl From<WireGuardError> for Error {
    fn from(e: WireGuardError) -> Self {
        Self::WireGuard(e)
    }
}
impl<'a, T> From<PoisonError<MutexGuard<'a, T>>> for Error {
    fn from(_: PoisonError<MutexGuard<'a, T>>) -> Self {
        Self::MutexPoisoned
    }
}

#[derive(Debug)]
struct InnerPacketIoQueues {
    rx_reserved: AtomicUsize,
    rx_queue: Queue<Vec<u8>>,
    tx_queue: Queue<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub struct PacketIoQueues(Arc<InnerPacketIoQueues>);

pub struct Peer {
    pub tunn: Tunn,
    pub addr: SocketAddr,
    pub conn: UdpSocket,

    pub queues: PacketIoQueues,
}

impl Peer {
    pub fn new(tunn: Tunn, addr: SocketAddr, conn: UdpSocket) -> Self {
        Self {
            tunn,
            addr,
            conn,

            queues: PacketIoQueues(Arc::new(InnerPacketIoQueues {
                rx_reserved: AtomicUsize::new(0),
                rx_queue: Queue::new(),
                tx_queue: Queue::new(),
            })),
        }
    }

    pub async fn begin_device(&mut self) -> Result<Infallible, Error> {
        let mut rx_buf = [0; 8 * 1024];

        loop {
            tokio::select! {
                packet = self.queues.0.tx_queue.pop() => {
                    self.handle_peer_tx_packet(&packet).await.unwrap();
                }
                read = self.conn.recv(&mut rx_buf) => {
                    let read = read?;
                    self.handle_peer_rx_packet(&rx_buf[0..read]).await.unwrap();
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    self.update_timers(&mut [0; 148]).await.unwrap();
                }
            }
        }
    }

    pub async fn handle_peer_tx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut out = vec![0; (packet.len() + 32).max(148)];

        let res = self.tunn.encapsulate(packet, &mut out);
        self.handle_tunnresult(res).await?;

        Ok(())
    }

    pub async fn handle_peer_rx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        tracing::info!(len = packet.len(), "recieved packet peer");

        let mut out = vec![0; 8 * 1024];

        let mut result: TunnResult;
        let mut first_loop = true;
        loop {
            result = self
                .tunn
                .decapsulate(None, if first_loop { packet } else { &[] }, &mut out);

            first_loop = false;

            match result {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                    self.conn.send(packet).await?;
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::info!("WRITE TO SMOL DEVICE");
                    self.queues.0.rx_queue.push(packet.to_vec());
                    break;
                }

                TunnResult::Done => break,
                TunnResult::Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Must be called often.
    pub async fn update_timers(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        tracing::debug!("updating timers...");

        let res = self.tunn.update_timers(buf);
        self.handle_tunnresult(res).await?;

        Ok(())
    }

    async fn handle_tunnresult(&self, val: TunnResult<'_>) -> Result<(), Error> {
        match val {
            // send to CF Warp
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                self.conn.send(packet).await?;
                Ok(())
            }
            // send to clients
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                tracing::info!("WRITE TO SMOL DEVICE");
                self.queues.0.rx_queue.push(packet.to_vec());
                Ok(())
            }
            // done
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(e.into()),
        }
    }
}

pub struct WgDevice(pub PacketIoQueues);

pub struct WgRxToken<'a>(&'a Queue<Vec<u8>>, &'a AtomicUsize);
impl<'a> RxToken for WgRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.0.try_pop().unwrap();
        tracing::info!(len = self.0.len());
        self.1.fetch_sub(1, Ordering::SeqCst);

        match Ipv4Packet::new_checked(&*packet) {
            Ok(parsed) => {
                tracing::info!(info = %PrettyPrinter::<Ipv4Packet<&[u8]>>::print(&parsed), "PACKET FROM PEER");
            }
            Err(e) => tracing::warn!(?e, "failed parsing packet"),
        }

        f(&mut packet)
    }
}

pub struct WgTxToken<'a>(&'a Queue<Vec<u8>>);
impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        tracing::debug!(?len, "transfer token consumed");
        let mut packet = vec![0; len];

        let ret = f(&mut packet);

        self.0.push(packet);

        ret
    }
}

impl Device for WgDevice {
    type RxToken<'a> = WgRxToken<'a>;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // TODO: I hate atomics. Nonetheless, I need to figure out if this is the right ordering.
        if self.0 .0.rx_reserved.load(Ordering::SeqCst) >= self.0 .0.rx_queue.len() {
            None
        } else {
            self.0 .0.rx_reserved.fetch_add(1, Ordering::SeqCst);

            Some((
                WgRxToken(&self.0 .0.rx_queue, &self.0 .0.rx_reserved),
                WgTxToken(&self.0 .0.tx_queue),
            ))
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        tracing::warn!("trans TOKEN");
        Some(WgTxToken(&self.0 .0.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}
