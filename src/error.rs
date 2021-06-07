use std::io;
use std::path::Path;

use nix::errno::Errno;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Crypt4GHFSError>;
const DEFAULT_LIBC_ERROR: Errno = Errno::ECANCELED;

#[derive(Error, Debug)]
pub enum Crypt4GHFSError {
    #[error("Path does not exist (path: {0})")]
    PathDoesNotExist(Box<Path>),
    #[error("Mounting process failed (ERROR = {0})")]
    MountError(String),
    #[error("Fork failed")]
    ForkFailed,
    #[error("Secret key not found (path: {0})")]
    SecretNotFound(Box<Path>),
    #[error("Error reading config (ERROR = {0})")]
    BadConfig(String),
    #[error("Unable to extract secret key (ERROR = {0})")]
    SecretKeyError(String),
    #[error("Connection url bad format")]
    BadConfigConnectionUrl,
    #[error("AMQP TlsConnector builder failed")]
    TlsConnectorError,
    #[error("Invalid checksum format")]
    InvalidChecksumFormat,
    #[error("No checksum found")]
    NoChecksum,
    #[error("Invalid connection_url scheme: {0}")]
    InvalidScheme(String),
    #[error("AMQP Error")]
    IoError(#[from] io::Error),
    #[error("CLI configuration failed (ERROR = {0})")]
    ConfigError(#[from] clap::Error),
    #[error("Config could not configure syslog (ERROR = {0})")]
    SysLogError(#[from] syslog::Error),
    #[error("Setting logger failed (ERROR = {0})")]
    LogError(#[from] log::SetLoggerError),
    #[error("File not opened")]
    FileNotOpened,
    #[error("Crypt4GH failed (ERROR = {0})")]
    Crypt4GHError(String),
    #[error("Libc failed (ERROR = {0})")]
    LibcError(#[from] nix::Error),
}

impl Crypt4GHFSError {
    pub fn to_raw_os_error(&self) -> i32 {
        match self {
            Self::IoError(io_error) => io_error.raw_os_error().unwrap_or(DEFAULT_LIBC_ERROR as i32),
            _ => DEFAULT_LIBC_ERROR as i32,
        }
    }
}
