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

    pub mtu: usize,

    pub tx_queue: VecDeque<Vec<u8>>,
    pub rx_queue: VecDeque<Vec<u8>>,

    pub needs_final_dispatch: bool,
    pub should_poll: bool,

    pub buf: Box<[u8]>,
}

impl Peer {
    pub fn new(tunn: Tunn, addr: SocketAddr, conn: UdpSocket, mtu: usize) -> Self {
        Self {
            tunn,
            addr,
            conn,
            mtu,

            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),

            needs_final_dispatch: false,
            should_poll: false,

            buf: Box::new([0; MAX_PACKET_SIZE]),
        }
    }

    #[instrument(skip(self, sleep, recv_buf))]
    pub async fn poll_device(
        &mut self,
        mut sleep: Pin<&mut Sleep>,
        recv_buf: &mut [u8],
    ) -> Result<(), Error> {
        while let Some(packet) = self.tx_queue.pop_back() {
            self.handle_peer_tx_packet(&packet).await?;
            self.should_poll = true;
        }

        while self.needs_final_dispatch {
            self.handle_peer_rx_packet(&[]).await?;
        }

        tokio::select! {
            ready = self.conn.readable() => {
                ready?;

                tracing::info!("READABLE");

                loop {
                    match self.conn.try_recv(recv_buf) {
                        Ok(len) => {
                            self.handle_peer_rx_packet(&recv_buf[..len]).await?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(?e, "failed to read from socket");
                        }
                    }
                }

                while self.needs_final_dispatch {
                    self.handle_peer_rx_packet(&[]).await?;
                }
            }
            () = sleep.as_mut() => {
                sleep.reset(Instant::now() + Duration::from_millis(250));

                self.update_timers(recv_buf).await?;
            }
        }

        Ok(())
    }

    #[instrument(skip(self, packet))]
    pub async fn handle_peer_tx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let res = self.tunn.encapsulate(packet, &mut self.buf);

        match res {
            // send to CF Warp
            TunnResult::WriteToNetwork(packet) => {
                tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                let sent = self.conn.send(packet).await?;
                if sent < packet.len() {
                    tracing::warn!(
                        sent = sent,
                        total = packet.len(),
                        "failed to send entire packet"
                    );
                    self.tx_queue.push_front(packet[sent..].to_vec());
                }

                Ok(())
            }
            TunnResult::Err(e) => Err(e.into()),
            res => {
                tracing::warn!(?res, "unexpected result from encapsulation");
                Ok(())
            }
        }
    }

    #[instrument(skip(self, packet))]
    pub async fn handle_peer_rx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        tracing::trace!(len = packet.len(), "recieved packet peer");

        let mut res = self.tunn.decapsulate(None, packet, &mut self.buf);

        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                    assert_eq!(self.conn.send(packet).await?, packet.len());
                    self.needs_final_dispatch = true;

                    break Ok(());
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::trace!("WRITE TO SMOL DEVICE");

                    self.rx_queue.push_front(packet.to_vec());
                    self.should_poll = true;

                    break Ok(());
                }

                TunnResult::Done => {
                    self.needs_final_dispatch = false;
                    break Ok(());
                }

                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    tracing::debug!("connection expired; re-handshaking");
                    res = self.tunn.format_handshake_initiation(&mut self.buf, true);
                    continue;
                }

                TunnResult::Err(e) => break Err(e.into()),
            }
        }
    }

    /// Must be called often.
    #[instrument(skip(self, buf))]
    pub async fn update_timers(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        //tracing::debug!("updating timers...");

        let mut res = self.tunn.update_timers(buf);

        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                    assert_eq!(self.conn.send(packet).await?, packet.len());

                    break Ok(());
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::trace!("WRITE TO SMOL DEVICE");

                    self.rx_queue.push_front(packet.to_vec());
                    self.should_poll = true;

                    break Ok(());
                }

                TunnResult::Done => {
                    break Ok(());
                }

                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    res = self.tunn.format_handshake_initiation(&mut self.buf, true);
                    continue;
                }

                TunnResult::Err(e) => break Err(e.into()),
            }
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
                tracing::trace!(info = %PrettyPrinter::<Ipv4Packet<&[u8]>>::print(&parsed), "PACKET FROM PEER");
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
        tracing::trace!(?len, "transfer token consumed");
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
            tracing::trace!(
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
        tracing::trace!("trans TOKEN");
        Some(WgTxToken {
            tx: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}
