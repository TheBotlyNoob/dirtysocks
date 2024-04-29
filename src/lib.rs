use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use untrusted::Input;

const USERNAME_PASSWORD_METHOD: u8 = 0x02;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid socks5 protocol")]
    Socks5Protocol,
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
            let (stream, client_addr) = self.listener.accept().await.unwrap();
            tokio::spawn(Self::handle_request(
                stream,
                client_addr,
                self.username.clone(),
                self.password.clone(),
            ));
        }
    }

    async fn handle_request(
        mut stream: TcpStream,
        _client_addr: SocketAddr,
        username: String,
        password: String,
    ) -> Result<(), Error> {
        let mut buffer = [0; 1024];

        let n = stream.read(&mut buffer).await?;

        let input = Input::from(&buffer[..n]);

        let version = input.read_all(Error::IncompleteRead, |input| {
            let version = input.read_byte()?;
            let nmethods = input.read_byte()?;
            let methods = input.read_bytes(nmethods as usize)?;

            if version != 0x05 {
                return Err(Error::InvalidVersion);
            }

            debug_assert_eq!(nmethods, methods.len() as u8);

            methods.read_all(Error::IncompleteRead, |methods| {
                while let Ok(method) = methods.read_byte() {
                    if method == USERNAME_PASSWORD_METHOD {
                        methods.skip_to_end();
                        return Ok(());
                    }
                }
                Err(Error::Socks5Protocol)
            })?; // we found it

            Ok(version)
        })?;

        stream
            .write_all(&[version, USERNAME_PASSWORD_METHOD])
            .await?;

        let n = stream.read(&mut buffer).await?;

        let input = Input::from(&buffer[..n]);

        let auth = input.read_all(Error::IncompleteRead, |input| {
            let version = input.read_byte()?;
            let ulen = input.read_byte()?;
            let given_username = input.read_bytes(ulen as usize)?;
            let plen = input.read_byte()?;
            let given_password = input.read_bytes(plen as usize)?;

            if version != 0x01 {
                return Err(Error::InvalidVersion);
            }

            if given_username.as_slice_less_safe() != username.as_bytes()
                || given_password.as_slice_less_safe() != password.as_bytes()
            {
                return Err(Error::InvalidCredentials);
            }

            Ok(())
        });

        match auth {
            Ok(_) => {
                stream.write_all(&[0x01, 0x00]).await?;
            }
            Err(Error::InvalidCredentials) => {
                stream.write_all(&[0x01, 0x01]).await?;
                stream.shutdown().await?;
            }
            Err(e) => return Err(e),
        };

        Ok(())
    }
}
