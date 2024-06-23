use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use smoltcp::wire::TcpPacket;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet parse error: {0}")]
    ParsePacket(#[from] smoltcp::wire::Error),
    #[error("wireguard error: {0:#?}")]
    WireGuard(WireGuardError),
}
// thiserror doesn't like WireGuardError for some reason
// so I have to implement From myself
impl From<WireGuardError> for Error {
    fn from(e: WireGuardError) -> Self {
        Self::WireGuard(e)
    }
}

/// When a packet is recieved from the wireguard peer and sent to the client.
#[derive(Clone, Debug)]
pub struct PacketToClient(pub Vec<u8>);
/// When a packet is recieved from a client and sent to the wireguard peer.
#[derive(Clone, Debug)]
pub struct PacketToPeer(pub Vec<u8>);

pub struct Peer {
    tunn: Tunn,
    pub addr: SocketAddr,
    pub conn: UdpSocket,
    pub on_packet: mpsc::Receiver<PacketToPeer>,
    pub buf: [u8; 1024],
    pub clients: HashMap<SocketAddr, mpsc::Sender<PacketToClient>>,
}

impl Peer {
    pub fn new(
        tunn: Tunn,
        addr: SocketAddr,
        conn: UdpSocket,
        on_packet: mpsc::Receiver<PacketToPeer>,
    ) -> Self {
        Self {
            tunn,
            addr,
            conn,
            on_packet,
            buf: [0; 1024],
            clients: HashMap::new(),
        }
    }

    pub async fn listen_for_packets(&mut self) -> Result<Infallible, Error> {
        loop {
            tokio::select! {
                Some(packet) = self.on_packet.recv() => self.handle_packet(packet).await?,
                () = tokio::time::sleep(Duration::from_secs(1)) => self.update_timers().await?,
            }
        }
    }

    pub async fn handle_packet(&mut self, packet: PacketToPeer) -> Result<(), Error> {
        let mut out = Vec::with_capacity(if packet.0.len() + 32 < 148 {
            148
        } else {
            packet.0.len() + 32
        });

        let res = self.tunn.encapsulate(&packet.0, &mut out);
        Self::handle_tunnresult(&mut self.conn, &self.clients, res).await?;

        Ok(())
    }

    pub fn add_client_addr(&mut self, addr: SocketAddr, sender: mpsc::Sender<PacketToClient>) {
        self.clients.insert(addr, sender);
    }

    /// Must be called often.
    pub async fn update_timers(&mut self) -> Result<(), Error> {
        tracing::debug!("updating timers...");

        let res = self.tunn.update_timers(&mut self.buf);
        Self::handle_tunnresult(&mut self.conn, &self.clients, res).await?;

        Ok(())
    }

    async fn handle_tunnresult(
        conn: &mut UdpSocket,
        clients: &HashMap<SocketAddr, mpsc::Sender<PacketToClient>>,
        val: TunnResult<'_>,
    ) -> Result<(), Error> {
        match val {
            // send to CF Warp
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(num_bytes = packet.len(), "writing to peer network");

                conn.send(packet).await?;
                Ok(())
            }
            // send to clients
            TunnResult::WriteToTunnelV4(packet, addr) => {
                Self::handle_wg_packet(packet, IpAddr::from(addr), clients).await
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                Self::handle_wg_packet(packet, IpAddr::from(addr), clients).await
            }
            // done
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(e.into()),
        }
    }

    async fn handle_wg_packet(
        packet: &[u8],
        ip: IpAddr,
        clients: &HashMap<SocketAddr, mpsc::Sender<PacketToClient>>,
    ) -> Result<(), Error> {
        let packet = TcpPacket::new_checked(packet)?;
        let port = packet.dst_port();

        let sock_addr = SocketAddr::from((ip, port));

        tracing::info!(dest_addr = ?ip, "sending packet to client...");

        clients
            .get(&sock_addr)
            .unwrap()
            .send(PacketToClient(packet.into_inner().to_vec()))
            .await
            .unwrap();

        Ok(())
    }
}
