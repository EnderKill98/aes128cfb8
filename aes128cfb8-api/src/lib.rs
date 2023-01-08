use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::net::UnixStream,
    },
    path::Path,
};

#[repr(u8)]
#[derive(Debug)]
pub enum Mode {
    Decrypt,
    Encrypt,
}

pub struct CryptorStreamRead<T> {
    inner: T,
    conn: UnixStream,
}

impl<T: Write + Read> CryptorStreamRead<T> {
    pub fn new(
        inner: T,
        aes128cfb8_server_path: impl AsRef<Path>,
        aes_key: &[u8; 16],
        iv: &[u8; 16],
    ) -> std::io::Result<Self> {
        Self::new_custom(inner, aes128cfb8_server_path, aes_key, iv, Mode::Decrypt)
    }

    pub fn new_custom(
        inner: T,
        aes128cfb8_server_path: impl AsRef<Path>,
        aes_key: &[u8; 16],
        iv: &[u8; 16],
        mode: Mode,
    ) -> std::io::Result<Self> {
        let mut conn = UnixStream::connect(aes128cfb8_server_path)?;
        conn.write_all(&[mode as u8])?;
        conn.write_all(aes_key)?;
        conn.write_all(iv)?;
        Ok(Self { inner, conn })
    }

    pub fn from_raw_fd(inner: T, raw_fd: RawFd) -> Self {
        Self {
            inner,
            conn: unsafe { UnixStream::from_raw_fd(raw_fd) },
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn into_inner_and_raw_fd(self) -> (T, RawFd) {
        (self.inner, self.conn.into_raw_fd())
    }

    pub fn into_raw_fd(self) -> RawFd {
        self.conn.into_raw_fd()
    }

    pub fn as_raw_fd(self) -> RawFd {
        self.conn.as_raw_fd()
    }
}

impl<T: Write + Read> Read for CryptorStreamRead<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_buf = vec![0u8; buf.len()];
        let read_count = self.inner.read(&mut read_buf)?;
        //let read_dec_count = self.decryptor.update(&read_buf[..read_count], buf)?;
        self.conn.write_all(&read_buf[..read_count])?;
        let mut read_dec_count_buf = [0u8; 4];
        self.conn.read_exact(&mut read_dec_count_buf)?;
        let read_dec_count = u32::from_be_bytes(read_dec_count_buf) as usize;
        self.conn.read_exact(&mut buf[..read_dec_count])?;

        #[cfg(feature = "log")]
        log::debug!(
            "Read {} bytes, after decrypt update {} bytes",
            read_count,
            read_dec_count
        );
        Ok(read_dec_count)
    }
}

pub struct CryptorStreamWrite<T> {
    inner: T,
    conn: UnixStream,
}

impl<T: Write + Read> CryptorStreamWrite<T> {
    pub fn new(
        inner: T,
        aes128cfb8_server_path: impl AsRef<Path>,
        aes_key: &[u8; 16],
        iv: &[u8; 16],
    ) -> std::io::Result<Self> {
        Self::new_custom(inner, aes128cfb8_server_path, aes_key, iv, Mode::Encrypt)
    }

    pub fn new_custom(
        inner: T,
        aes128cfb8_server_path: impl AsRef<Path>,
        aes_key: &[u8; 16],
        iv: &[u8; 16],
        mode: Mode,
    ) -> std::io::Result<Self> {
        let mut conn = UnixStream::connect(aes128cfb8_server_path)?;
        conn.write_all(&[mode as u8])?;
        conn.write_all(aes_key)?;
        conn.write_all(iv)?;
        Ok(Self { inner, conn })
    }

    pub fn from_raw_fd(inner: T, raw_fd: RawFd) -> Self {
        Self {
            inner,
            conn: unsafe { UnixStream::from_raw_fd(raw_fd) },
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn into_inner_and_raw_fd(self) -> (T, RawFd) {
        (self.inner, self.conn.into_raw_fd())
    }

    pub fn into_raw_fd(self) -> RawFd {
        self.conn.into_raw_fd()
    }

    pub fn as_raw_fd(self) -> RawFd {
        self.conn.as_raw_fd()
    }
}

impl<T: Write + Read> Write for CryptorStreamWrite<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut write_buf = vec![0u8; buf.len()];
        //let write_count = self.encryptor.update(&buf, &mut write_buf)?;
        self.conn.write_all(buf)?;
        let mut write_count_buf = [0u8; 4];
        self.conn.read_exact(&mut write_count_buf)?;
        let write_count = u32::from_be_bytes(write_count_buf) as usize;
        self.conn.read_exact(&mut write_buf[..write_count])?;

        let final_count = self.inner.write(&write_buf[..write_count])?;
        #[cfg(feature = "log")]
        log::debug!(
            "Wanted write {} bytes, encrypted {} bytes, passed {} bytes",
            buf.len(),
            write_count,
            final_count
        );
        Ok(final_count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
