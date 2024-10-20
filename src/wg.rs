use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    wire::{Ipv4Packet, PrettyPrinter},
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    sync::{MutexGuard, PoisonError},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, Sleep},
};
use tracing::instrument;

use crate::MAX_PACKET_SIZE;

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

pub struct Peer {
    pub tunn: Tunn,
    pub addr: SocketAddr,
    pub conn: UdpSocket,

    pub tx_queue: VecDeque<Vec<u8>>,
    pub rx_queue: VecDeque<Vec<u8>>,

    pub buf: Box<[u8]>,
}

impl Peer {
    pub fn new(tunn: Tunn, addr: SocketAddr, conn: UdpSocket) -> Self {
        Self {
            tunn,
            addr,
            conn,

            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),

            buf: Box::new([0; MAX_PACKET_SIZE]),
        }
    }

    #[instrument(skip(self, sleep))]
    pub async fn poll_device(&mut self, mut sleep: Pin<&mut Sleep>) -> Result<(), Error> {
        let Self {
            ref mut tunn,
            ref conn,
            ref mut buf,
            ref mut tx_queue,
            ..
        } = self;

        for packet in tx_queue.drain(..) {
            Self::handle_peer_tx_packet(tunn, conn, buf, &packet).await?;
        }

        let mut rx_buf = Box::new([0; MAX_PACKET_SIZE]);

        tokio::select! {
            ready = conn.recv(&mut *rx_buf) => {
                let len = ready?;

                self.handle_peer_rx_packet(&rx_buf[..len]).await?;
            }
            () = sleep.as_mut() => {
                sleep.reset(Instant::now() + Duration::from_millis(250));

                self.update_timers(&mut [0; 148]).await.unwrap();
            }
        }

        Ok(())
    }

    #[instrument(skip(tunn, conn, buf, packet))]
    pub async fn handle_peer_tx_packet(
        tunn: &mut Tunn,
        conn: &UdpSocket,
        buf: &mut [u8],
        packet: &[u8],
    ) -> Result<(), Error> {
        let res = tunn.encapsulate(packet, buf);

        match res {
            // send to CF Warp
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                assert_eq!(conn.send(packet).await?, packet.len());

                Ok(())
            }
            TunnResult::Err(e) => Err(e.into()),
            _ => Ok(()),
        }
    }

    #[instrument(skip(self, packet))]
    pub async fn handle_peer_rx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        tracing::info!(len = packet.len(), "recieved packet peer");

        let mut result: TunnResult;
        let mut first_loop = true;
        loop {
            result =
                self.tunn
                    .decapsulate(None, if first_loop { packet } else { &[] }, &mut self.buf);

            first_loop = false;

            match result {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                    assert_eq!(self.conn.send(packet).await?, packet.len());

                    continue;
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::info!("WRITE TO SMOL DEVICE");

                    self.rx_queue.push_front(packet.to_vec());

                    break;
                }

                TunnResult::Done => break,
                TunnResult::Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Must be called often.
    #[instrument(skip(self, buf))]
    pub async fn update_timers(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        //tracing::debug!("updating timers...");

        let res = self.tunn.update_timers(buf);
        match res {
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                assert_eq!(self.conn.send(packet).await?, packet.len());

                Ok(())
            }

            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                unreachable!()
            }

            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(e.into()),
        }
    }
}
pub struct WgRxToken {
    packet: Vec<u8>,
}
impl RxToken for WgRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        match Ipv4Packet::new_checked(&*self.packet) {
            Ok(parsed) => {
                tracing::info!(info = %PrettyPrinter::<Ipv4Packet<&[u8]>>::print(&parsed), "PACKET FROM PEER");
            }
            Err(e) => tracing::warn!(?e, "failed parsing packet"),
        }

        f(&mut self.packet)
    }
}

pub struct WgTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}
impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        tracing::debug!(?len, "transfer token consumed");
        let mut packet = vec![0; len];

        let ret = f(&mut packet);

        self.tx.push_front(packet);

        ret
    }
}

impl Device for Peer {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_back() {
            tracing::info!(
                len = packet.len(),
                "recieved packet from peer; recv token retrieved"
            );
            Some((
                WgRxToken { packet },
                WgTxToken {
                    tx: &mut self.tx_queue,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        tracing::warn!("trans TOKEN");
        Some(WgTxToken {
            tx: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1280;
        capabilities
    }
}
