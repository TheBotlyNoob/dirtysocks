use std::{convert::Infallible, net::SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use untrusted::Input;

pub const SOCKS_VERSION: u8 = 0x05;
pub const USERNAME_PASSWORD_VERSION: u8 = 0x01;

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
}
impl From<untrusted::EndOfInput> for Error {
    fn from(_: untrusted::EndOfInput) -> Self {
        Error::UnexpectedEOI
    }
}

pub struct Socks5Server {
    pub listener: TcpListener,
    pub username: String,
    pub password: String,
}

impl Socks5Server {
    pub async fn new(
        listener: TcpListener,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Socks5Server {
            listener,
            username: username.into(),
            password: password.into(),
        }
    }

    pub async fn listen(&self) {
        loop {
            while let Ok((stream, client_addr)) = self.listener.accept().await {
                tokio::spawn(
                    TcpClientHandler::new(
                        stream,
                        client_addr,
                        self.username.clone(),
                        self.password.clone(),
                    )
                    .run(),
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum AuthMethod {
    NoAuthRequired = 0x00,
    GssApi = 0x01,
    UsernamePassword = 0x02,
    NoneAcceptable = 0xFF,
}

struct TcpClientHandler {
    stream: TcpStream,
    client_addr: SocketAddr,
    buf: [u8; 1024],
    username: String,
    password: String,
}
impl TcpClientHandler {
    fn new(stream: TcpStream, client_addr: SocketAddr, username: String, password: String) -> Self {
        Self {
            stream,
            client_addr,
            buf: [0; 1024],
            username,
            password,
        }
    }
    async fn run(mut self) -> Result<Infallible, Error> {
        self.init_conn().await?;
        loop {}
    }
    /// Authorizes with the client and checks version.
    async fn init_conn(&mut self) -> Result<bool, Error> {
        let input = self.stream.read(&mut self.buf).await?;
        let input = Input::from(&self.buf[..input]);

        let method = Self::parse_initial_packet(input)?;

        self.stream
            .write_all(&[SOCKS_VERSION, method as u8])
            .await?;
        if method == AuthMethod::NoneAcceptable {
            return Err(Error::AuthMethodNotFound);
        }

        todo!();
    }

    fn parse_username_password_request(input: Input<'_>) -> Result<(&[u8], &[u8]), Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version 
        })
    }

    fn parse_initial_packet(input: Input<'_>) -> Result<AuthMethod, Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let nmethods = reader.read_byte()?;
            let methods = reader.read_bytes(nmethods as usize)?;

            if version != SOCKS_VERSION {
                return Err(Error::InvalidVersion);
            }

            if Self::contains_method(methods, AuthMethod::UsernamePassword) {
                Ok(AuthMethod::UsernamePassword)
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