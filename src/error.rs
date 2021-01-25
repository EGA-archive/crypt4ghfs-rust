use std::{io, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Crypt4GHFSError {
	#[cfg(feature = "rabbitmq")]
	#[error("AMQP Connection failed (ERROR = {0:?})")]
	ConnectionError(Option<amiquip::Error>),
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
	#[cfg(feature = "rabbitmq")]
	#[error("AMQP Error")]
	AMQPError(#[from] amiquip::Error),
	#[error("IO failed")]
	IoError(#[from] io::Error),
}
