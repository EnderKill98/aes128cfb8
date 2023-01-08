use aes128cfb8_api::Mode;
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{unix::SocketAddr, UnixListener, UnixStream},
};

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;

#[derive(Parser)]
struct Opts {
    /// Where to create the unix domain socket at
    socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    env_logger::builder().format_timestamp_millis().init();

    let listener = UnixListener::bind(opts.socket)?;
    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(async move {
            info!("[{addr:?}] Connection opened");
            if let Err(err) = handle_client(socket, &addr).await {
                warn!("[{addr:?}] Connection closed with error: {err:?}");
            } else {
                info!("[{addr:?}] Connection closed");
            }
        });
    }
}

async fn handle_client(mut socket: UnixStream, addr: &SocketAddr) -> Result<()> {
    let mut mode = [0u8; 1];
    let mut aes_key = [0u8; 16];
    let mut iv = [0u8; 16];
    socket.read_exact(&mut mode).await.context("Read mode")?;
    socket.read_exact(&mut aes_key).await.context("Read aes key")?;
    socket.read_exact(&mut iv).await.context("Read iv")?;
    let mode = if mode[0] == Mode::Decrypt as u8 {
        Mode::Decrypt
    } else if mode[0] == Mode::Encrypt as u8 {
        Mode::Encrypt
    } else {
        bail!("Invalid mode: {}!", mode[0])
    };
    let mut crypter = openssl::symm::Crypter::new(
        openssl::symm::Cipher::aes_128_cfb8(),
        match mode {
            Mode::Decrypt => openssl::symm::Mode::Decrypt,
            Mode::Encrypt => openssl::symm::Mode::Encrypt,
        },
        &aes_key,
        Some(&iv),
    )?;

    info!("[{addr:?}] Initialized with AES Key, IV and Mode {mode:?}");

    let mut in_buf = [0u8; 1024 * 8];
    let mut out_buf = [0u8; 1024 * 8 + 16];
    loop {
        let bytes_read = match socket.read(&mut in_buf).await {
            Ok(0) => return Ok(()),
            Ok(bytes_read) => bytes_read,
            Err(err) => return Err(err).context("Read bytes"),
        };

        let write_bytes = crypter
            .update(&in_buf[..bytes_read], &mut out_buf)
            .context("Perform en-/decryption")?;
        socket
            .write_u32(write_bytes as u32)
            .await
            .context("Write processed bytes len")?;
        socket
            .write_all(&out_buf[..write_bytes])
            .await
            .context("Write processed bytes")?;
        #[cfg(not(feature = "disable_debug"))]
        debug!("[{addr:?}] Processed {bytes_read} bytes.");
    }
}
