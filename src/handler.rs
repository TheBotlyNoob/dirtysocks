#![allow(clippy::missing_errors_doc)]
use hickory_resolver::TokioAsyncResolver;
use seq_macro::seq;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::tcp,
};
use std::{
    marker::PhantomData,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use strum::FromRepr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use untrusted::Input;

use crate::Error;

pub const SOCKS_VERSION: u8 = 0x05;
pub const USERNAME_PASSWORD_VERSION: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
#[repr(u8)]
enum AuthMethod {
    NoAuthRequired = 0x00,
    GssApi = 0x01,
    UsernamePassword = 0x02,
    NoneAcceptable = 0xFF,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
#[repr(u8)]
enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Address<'input> {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    DomainName(&'input str, u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
#[repr(u8)]
enum CommandType {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Command<'input> {
    addr: Address<'input>,
    ty: CommandType,
    version: u8,
}

/// RFC 1928:
/// ```text
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
///      +----+-----+-------+------+----------+----------+
///      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///      +----+-----+-------+------+----------+----------+
///      | 1  |  1  | X'00' |  1   | Variable |    2     |
///      +----+-----+-------+------+----------+----------+
///
///   Where:
///
///        o  VER    protocol version: X'05'
///        o  REP    Reply field:
///           o  X'00' succeeded
///           o  X'01' general SOCKS server failure
///           o  X'02' connection not allowed by ruleset
///           o  X'03' Network unreachable
///           o  X'04' Host unreachable
///           o  X'05' Connection refused
///           o  X'06' TTL expired
///           o  X'07' Command not supported
///           o  X'08' Address type not supported
///           o  X'09' to X'FF' unassigned
///        o  RSV    RESERVED
///        o  ATYP   address type of following address
///           o  IP V4 address: X'01'
///           o  DOMAINNAME: X'03'
///           o  IP V6 address: X'04'
///        o  BND.ADDR       server bound address
///        o  BND.PORT       server bound port in network octet order
/// ```
pub struct Reply {
    pub version: u8,
    pub reply: u8,
    pub reserved: u8,
    pub address: SocketAddr,
}

impl Reply {
    #[must_use]
    pub const fn new(reply: u8, address: SocketAddr) -> Self {
        Self {
            version: SOCKS_VERSION,
            reply,
            reserved: 0,
            address,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> ([u8; 6 + 16], usize) {
        let mut buf = [0; 6 + 16]; // 6 bytes for fixed fields, 16 for a possible ipv6 address
        let addr_len = if self.address.is_ipv4() { 4 } else { 16 };
        buf[0] = self.version;
        buf[1] = self.reply;
        buf[2] = self.reserved;
        buf[3] = if self.address.is_ipv4() {
            AddressType::Ipv4 as u8
        } else {
            AddressType::Ipv6 as u8
        };
        match self.address {
            SocketAddr::V4(addr) => buf[4..4 + 4].copy_from_slice(&addr.ip().octets()),
            SocketAddr::V6(addr) => buf[4..4 + 16].copy_from_slice(&addr.ip().octets()),
        }
        buf[4 + addr_len..6 + addr_len].copy_from_slice(&self.address.port().to_be_bytes());
        (buf, 6 + addr_len)
    }
}

pub struct Initial;
pub struct Authorized;
pub struct Piping;

pub struct Connection<State> {
    stream: TcpStream,
    client_addr: SocketAddr,
    pub socket_handle: SocketHandle,
    resolver: TokioAsyncResolver,
    timeout: Duration,
    pub buf: [u8; 8 * 1024],
    user_pass: Option<crate::UserPass>,

    state: State,
}
impl Connection<Initial> {
    pub fn new(
        stream: TcpStream,
        client_addr: SocketAddr,
        socket_handle: SocketHandle,
        resolver: TokioAsyncResolver,
        timeout: Duration,
        user_pass: Option<crate::UserPass>,
    ) -> Self {
        Self {
            stream,
            client_addr,
            socket_handle,
            resolver,
            timeout,
            buf: [0; 8 * 1024],
            user_pass,
            state: Initial,
        }
    }

    /// Authorizes with the client and checks version.
    pub async fn init_conn(mut self) -> Result<Connection<Authorized>, Error> {
        let input = self.stream.read(&mut self.buf).await?;
        let input = Input::from(&self.buf[..input]);

        let method = Self::parse_initial_packet(input, self.user_pass.is_some())?;

        self.stream
            .write_all(&[SOCKS_VERSION, method as u8])
            .await?;

        if method == AuthMethod::NoneAcceptable {
            tracing::warn!("no acceptable auth method found");
            return Err(Error::AuthMethodNotFound);
        }

        if let Some(user_pass) = self.user_pass.as_ref() {
            let input = self.stream.read(&mut self.buf).await?;
            let input = Input::from(&self.buf[..input]);
            let (username, password) = Self::parse_username_password_request(input)?;

            let status = u8::from(
                !(username == user_pass.username.as_bytes()
                    || password == user_pass.password.as_bytes()),
            );

            self.stream
                .write_all(&[USERNAME_PASSWORD_VERSION, status])
                .await?;

            if status != 0x00 {
                tracing::warn!("invalid credentials");
                return Err(Error::InvalidCredentials);
            }
        }

        Ok(change_state(self, Authorized))
    }

    fn parse_username_password_request(input: Input<'_>) -> Result<(&[u8], &[u8]), Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let uname_len = reader.read_byte()?;
            let username = reader.read_bytes(uname_len as usize)?;
            let pass_len = reader.read_byte()?;
            let password = reader.read_bytes(pass_len as usize)?;

            if version != USERNAME_PASSWORD_VERSION {
                return Err(Error::InvalidVersion);
            }

            Ok((username.as_slice_less_safe(), password.as_slice_less_safe()))
        })
    }

    fn parse_initial_packet(input: Input<'_>, use_auth: bool) -> Result<AuthMethod, Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let num_methods = reader.read_byte()?;
            let methods = reader.read_bytes(num_methods as usize)?;

            if version != SOCKS_VERSION {
                return Err(Error::InvalidVersion);
            }

            if use_auth && Self::contains_method(methods, AuthMethod::UsernamePassword) {
                Ok(AuthMethod::UsernamePassword)
            } else if !use_auth && Self::contains_method(methods, AuthMethod::NoAuthRequired) {
                Ok(AuthMethod::NoAuthRequired)
            } else {
                Ok(AuthMethod::NoneAcceptable)
            }
        })
    }

    fn contains_method(input: Input<'_>, method: AuthMethod) -> bool {
        input
            .read_all((), |reader| {
                while let Ok(allowed_method) = reader.read_byte() {
                    if allowed_method == method as u8 {
                        reader.skip_to_end();
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .unwrap_or(false)
    }
}

impl Connection<Authorized> {
    pub async fn handle_request(mut self) -> Result<(SocketAddr, Connection<Piping>), Error> {
        let input = self.stream.read(&mut self.buf).await?;
        let input = Input::from(&self.buf[..input]);

        let mut domain_buf = [0; u8::MAX as usize]; // max domain length for socks5 is the size of a byte
        let command = Self::parse_request(&mut domain_buf, input)?;

        tracing::debug!(?command);

        let dest_sock_addr = match command.addr {
            Address::Ipv4(addr) => SocketAddr::from(addr),
            Address::Ipv6(addr) => SocketAddr::from(addr),
            Address::DomainName(domain, port) => {
                tracing::debug!(?domain, ?port, "resolving domain");
                let ips = self.resolver.lookup_ip(domain).await?;

                let Some(ip) = ips.iter().next() else {
                    let (reply_buf, reply_buf_len) =
                        Reply::new(0x04, SocketAddr::from(([0, 0, 0, 0], 0))).to_bytes();
                    self.stream.write_all(&reply_buf[..reply_buf_len]).await?;
                    return Err(Error::NoSuchHost);
                };

                SocketAddr::from((ip, port))
            }
        };

        let piping = match command.ty {
            CommandType::Connect => self.handle_connect(dest_sock_addr).await?,
            CommandType::Bind => {
                todo!()
            }
            CommandType::UdpAssociate => {
                todo!()
            }
        };

        Ok((dest_sock_addr, piping))
    }

    /// ```text
    /// CONNECT
    /// In the reply to a CONNECT, BND.PORT contains the port number that the
    /// server assigned to connect to the target host, while BND.ADDR
    /// contains the associated IP address.  The supplied BND.ADDR is often
    /// different from the IP address that the client uses to reach the SOCKS
    /// server, since such servers are often multi-homed.  It is expected
    /// that the SOCKS server will use DST.ADDR and DST.PORT, and the
    /// client-side source address and port in evaluating the CONNECT
    /// request.
    /// ```
    async fn handle_connect(
        mut self,
        _dest_sock_addr: SocketAddr,
    ) -> Result<Connection<Piping>, Error> {
        tracing::info!("handling connect");

        // 0x00 reply means success
        // 0.0.0.0:0 means the same address and port
        let (reply_buf, reply_buf_len) =
            Reply::new(0x00, SocketAddr::from(([0, 0, 0, 0], 0))).to_bytes();

        self.stream.write_all(&reply_buf[..reply_buf_len]).await?;

        Ok(change_state(self, Piping))
    }

    fn parse_request<'domain>(
        domain_buf: &'domain mut [u8],
        input: Input<'_>,
    ) -> Result<Command<'domain>, Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let ty =
                CommandType::from_repr(reader.read_byte()?).ok_or(Error::InvalidCommandType)?;
            let _reserved = reader.read_byte()?;
            let address_type =
                AddressType::from_repr(reader.read_byte()?).ok_or(Error::InvalidAddressType)?;

            let addr = match address_type {
                AddressType::Ipv4 => Address::Ipv4(SocketAddrV4::new(
                    seq!(_ in 0..4 {
                        [
                            #(
                                reader.read_byte()?,
                            )*
                        ]
                    })
                    .into(),
                    u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]),
                )),
                AddressType::Ipv6 => Address::Ipv6(SocketAddrV6::new(
                    seq!(_ in 0..16 {
                        [
                            #(
                                reader.read_byte()?,
                            )*
                        ]
                    })
                    .into(),
                    u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]),
                    0,
                    0,
                )),
                AddressType::DomainName => {
                    let len = reader.read_byte()?;
                    let domain = reader.read_bytes(len as usize)?;
                    let port = u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]);

                    let domain_slice = &mut domain_buf[..len as usize];

                    domain_slice.copy_from_slice(domain.as_slice_less_safe());

                    Address::DomainName(std::str::from_utf8(domain_slice)?, port)
                }
            };

            Ok(Command { addr, ty, version })
        })
    }
}

impl Connection<Piping> {
    pub async fn pipe(mut self, resp_len: Option<usize>) -> Result<(usize, Self), Error> {
        tracing::info!(?resp_len, "piping");
        if let Some(resp_len) = resp_len {
            tracing::info!(?resp_len, "recv'd");
            self.stream.write_all(&self.buf[0..resp_len]).await?;
        }

        let read = self.stream.read(&mut self.buf).await?;

        Ok((read, self))
    }
}

fn change_state<O, N>(old: Connection<O>, new_state: N) -> Connection<N> {
    Connection {
        stream: old.stream,
        client_addr: old.client_addr,
        socket_handle: old.socket_handle,
        resolver: old.resolver,
        timeout: old.timeout,
        buf: old.buf,
        user_pass: old.user_pass,
        state: new_state,
    }
}
