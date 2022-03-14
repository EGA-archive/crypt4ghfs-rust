use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crypt4gh::error::Crypt4GHError;
use crypt4gh::Keys;
use fuser::MountOption;
use itertools::Itertools;
use rpassword::prompt_password;
use serde::Deserialize;

use crate::error::Crypt4GHFSError;

const PASSPHRASE: &str = "C4GH_PASSPHRASE";

#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
	#[serde(alias = "CRITICAL")]
	Critical,
	Warn,
	Info,
	Debug,
	#[serde(alias = "NOTSET")]
	Trace,
}

#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Facility {
	Kern,
	User,
	Mail,
	Daemon,
	Auth,
	Syslog,
	Lpr,
	News,
	Uucp,
	Cron,
	Authpriv,
	Ftp,
	Local0,
	Local1,
	Local2,
	Local3,
	Local4,
	Local5,
	Local6,
	Local7,
}

#[derive(Deserialize, Debug)]
pub struct Default {
	extensions: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct Fuse {
	options: Option<Vec<String>>,
	rootdir: String,
	cache_directories: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct Crypt4GH {
	#[serde(rename = "seckey")]
	seckey_path: Option<String>,
	recipients: Option<Vec<String>>,
	include_myself_as_recipient: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct LoggerConfig {
	pub log_level: LogLevel,
	pub use_syslog: bool,
	pub log_facility: Option<Facility>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Config {
	default: Default,
	pub logger: LoggerConfig,
	fuse: Fuse,
	crypt4gh: Crypt4GH,
}

impl Config {
	pub fn new_with_defaults(rootdir: String, seckey_path: Option<String>) -> Self {
		Self {
			default: Default { extensions: vec![] },
			fuse: Fuse {
				rootdir,
				options: Some(vec!["ro".into(), "default_permissions".into(), "auto_unmount".into()]),
				cache_directories: Some(true),
			},
			crypt4gh: Crypt4GH {
				seckey_path,
				recipients: Some(vec![]),
				include_myself_as_recipient: Some(true),
			},
			logger: LoggerConfig {
				log_level: LogLevel::Info,
				use_syslog: false,
				log_facility: None,
			},
		}
	}

	#[must_use]
	pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
		self.default.extensions = extensions;
		self
	}

	#[must_use]
	pub const fn with_log_level(mut self, log_level: LogLevel) -> Self {
		self.logger.log_level = log_level;
		self
	}

	pub fn get_options(&self) -> Vec<MountOption> {
		self.fuse.options.clone().map_or_else(
			|| vec![MountOption::RW, MountOption::DefaultPermissions],
			|options| {
				options
					.iter()
					.map(String::as_str)
					.map(str_to_mount_option)
					.inspect(|option| {
						log::info!("+ fuse option: {:?}", option);
					})
					.collect()
			},
		)
	}

	pub const fn get_cache(&self) -> bool {
		if let Some(cache_directories) = self.fuse.cache_directories {
			return cache_directories;
		}
		true
	}

	pub fn get_extensions(&self) -> Vec<String> {
		self.default.extensions.clone()
	}

	pub fn get_secret_key(&self) -> Result<Option<Vec<u8>>, Crypt4GHFSError> {
		match &self.crypt4gh.seckey_path {
			Some(seckey_path_str) => {
				let seckey_path = Path::new(&seckey_path_str);
				log::info!("Loading secret key from {}", seckey_path.display());

				if !seckey_path.is_file() {
					return Err(Crypt4GHFSError::SecretNotFound(seckey_path.into()));
				}

				let callback: Box<dyn Fn() -> Result<String, Crypt4GHError>> = match std::env::var(PASSPHRASE) {
					Ok(_) => {
						log::warn!("Warning: Using a passphrase in an environment variable is insecure");
						Box::new(|| std::env::var(PASSPHRASE).map_err(|e| Crypt4GHError::NoPassphrase(e.into())))
					},
					Err(_) => Box::new(|| {
						prompt_password(format!("Passphrase for {}: ", seckey_path.display()))
							.map_err(|e| Crypt4GHError::NoPassphrase(e.into()))
					}),
				};

				let key = crypt4gh::keys::get_private_key(seckey_path, callback)
					.map_err(|e| Crypt4GHFSError::SecretKeyError(e.to_string()))?;

				Ok(Some(key))
			},
			None => Ok(None),
		}
	}

	pub fn get_recipients(&self, seckey: &[u8]) -> HashSet<Keys> {
		let recipient_paths = &self.crypt4gh.recipients.clone().unwrap_or_default();

		let mut recipient_pubkeys: HashSet<_> = recipient_paths
			.iter()
			.map(Path::new)
			.filter(|path| path.exists())
			.filter_map(|path| {
				log::debug!("Recipient pubkey path: {}", path.display());
				crypt4gh::keys::get_public_key(path).ok()
			})
			.unique()
			.map(|key| Keys {
				method: 0,
				privkey: seckey.to_vec(),
				recipient_pubkey: key,
			})
			.collect();

		if self.crypt4gh.include_myself_as_recipient.unwrap_or(true) {
			let k = crypt4gh::keys::get_public_key_from_private_key(seckey)
				.expect("Unable to extract public key from seckey");
			recipient_pubkeys.insert(Keys {
				method: 0,
				privkey: seckey.to_vec(),
				recipient_pubkey: k,
			});
		}

		recipient_pubkeys
	}

	pub const fn get_log_level(&self) -> LogLevel {
		self.logger.log_level
	}

	pub fn get_rootdir(&self) -> String {
		self.fuse.rootdir.to_string()
	}

	pub fn from_file(mut config_file: File) -> Result<Self, Crypt4GHFSError> {
		let mut config_string = String::new();
		config_file
			.read_to_string(&mut config_string)
			.map_err(|e| Crypt4GHFSError::BadConfig(e.to_string()))?;
		let config_toml = toml::from_str(config_string.as_str()).map_err(|e| Crypt4GHFSError::BadConfig(e.to_string()));
		config_toml
	}

	pub fn get_facility(&self) -> syslog::Facility {
		match self.logger.log_facility.unwrap_or(Facility::User) {
			Facility::Kern => syslog::Facility::LOG_KERN,
			Facility::User => syslog::Facility::LOG_USER,
			Facility::Mail => syslog::Facility::LOG_MAIL,
			Facility::Daemon => syslog::Facility::LOG_DAEMON,
			Facility::Auth => syslog::Facility::LOG_AUTH,
			Facility::Syslog => syslog::Facility::LOG_SYSLOG,
			Facility::Lpr => syslog::Facility::LOG_LPR,
			Facility::News => syslog::Facility::LOG_NEWS,
			Facility::Uucp => syslog::Facility::LOG_UUCP,
			Facility::Cron => syslog::Facility::LOG_CRON,
			Facility::Authpriv => syslog::Facility::LOG_AUTHPRIV,
			Facility::Ftp => syslog::Facility::LOG_FTP,
			Facility::Local0 => syslog::Facility::LOG_LOCAL0,
			Facility::Local1 => syslog::Facility::LOG_LOCAL1,
			Facility::Local2 => syslog::Facility::LOG_LOCAL2,
			Facility::Local3 => syslog::Facility::LOG_LOCAL3,
			Facility::Local4 => syslog::Facility::LOG_LOCAL4,
			Facility::Local5 => syslog::Facility::LOG_LOCAL5,
			Facility::Local6 => syslog::Facility::LOG_LOCAL6,
			Facility::Local7 => syslog::Facility::LOG_LOCAL7,
		}
	}

	pub fn setup_logger(&self) -> Result<(), Crypt4GHFSError> {
		let log_level: LogLevel = if let Ok(log_level_str) = std::env::var("RUST_LOG") {
			log_level_str
				.as_str()
				.try_into()
				.expect("Unable to parse RUST_LOG environment variable")
		}
		else {
			let log_level = self.get_log_level();
			let log_level_str = match log_level {
				LogLevel::Critical => "error",
				LogLevel::Warn => "warn",
				LogLevel::Info => "info",
				LogLevel::Debug => "debug",
				LogLevel::Trace => "trace",
			};
			std::env::set_var("RUST_LOG", log_level_str);
			log_level
		};

		// Choose logger
		if self.logger.use_syslog {
			syslog::init(self.get_facility(), log_level.into(), None)?;
		}
		else {
			let _ = pretty_env_logger::try_init(); // Ignore error
		}

		Ok(())
	}
}

impl TryFrom<&str> for LogLevel {
	type Error = Crypt4GHFSError;

	fn try_from(level: &str) -> Result<Self, Self::Error> {
		match level {
			"error" => Ok(Self::Critical),
			"warn" => Ok(Self::Warn),
			"info" => Ok(Self::Info),
			"debug" => Ok(Self::Debug),
			"trace" => Ok(Self::Trace),
			_ => Err(Crypt4GHFSError::BadConfig("Wrong log level".into())),
		}
	}
}

impl From<LogLevel> for log::LevelFilter {
	fn from(val: LogLevel) -> Self {
		match val {
			LogLevel::Critical => Self::Error,
			LogLevel::Warn => Self::Warn,
			LogLevel::Info => Self::Info,
			LogLevel::Debug => Self::Debug,
			LogLevel::Trace => Self::Trace,
		}
	}
}

fn str_to_mount_option(s: &str) -> MountOption {
	match s {
		"auto_unmount" => MountOption::AutoUnmount,
		"allow_other" => MountOption::AllowOther,
		"allow_root" => MountOption::AllowRoot,
		"default_permissions" => MountOption::DefaultPermissions,
		"dev" => MountOption::Dev,
		"nodev" => MountOption::NoDev,
		"suid" => MountOption::Suid,
		"nosuid" => MountOption::NoSuid,
		"ro" => MountOption::RO,
		"rw" => MountOption::RW,
		"exec" => MountOption::Exec,
		"noexec" => MountOption::NoExec,
		"atime" => MountOption::Atime,
		"noatime" => MountOption::NoAtime,
		"dirsync" => MountOption::DirSync,
		"sync" => MountOption::Sync,
		"async" => MountOption::Async,
		x if x.starts_with("fsname=") => MountOption::FSName(x[7..].into()),
		x if x.starts_with("subtype=") => MountOption::Subtype(x[8..].into()),
		x => MountOption::CUSTOM(x.into()),
	}
}
