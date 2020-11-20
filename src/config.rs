use anyhow::Result;
use anyhow::{anyhow, ensure};
use crypt4gh::{self, Keys};
use itertools::Itertools;
use rpassword::read_password_from_tty;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ffi::OsString, fs::File, io::Read, path::Path};
use toml;

const PASSPHRASE: &str = "C4GH_PASSPHRASE";

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
	#[serde(alias = "CRITICAL")]
	Error,
	Warn,
	Info,
	Debug,
	#[serde(alias = "NOTSET")]
	Trace,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FuseMountOption {
	FSName(String),
	Subtype(String),
	Custom(String),
	AllowOther,
	AllowRoot,
	AutoUnmount,
	DefaultPermissions,
	Dev,
	NoDev,
	Suid,
	NoSuid,
	Ro,
	Rw,
	Exec,
	NoExec,
	Atime,
	NoAtime,
	DirSync,
	Sync,
	Async,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Default {
	pub rootdir: String,
	pub log_level: Option<LogLevel>,
	pub include_crypt4gh_log: Option<bool>,
	pub extension: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Fuse {
	pub options: Option<Vec<FuseMountOption>>,
	pub cache_directories: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypt4GH {
	pub seckey: String,
	pub recipient_keys: Option<Vec<String>>,
	pub include_myself_as_recipient: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Config {
	pub default: Default,
	pub fuse: Option<Fuse>,
	pub crypt4gh: Crypt4GH,
}

impl Config {
	pub fn get_options(&self, default: Vec<FuseMountOption>) -> Vec<FuseMountOption> {
		if let Some(fuse) = &self.fuse {
			if let Some(options) = &fuse.options {
				return options.to_vec();
			}
		}
		default
	}

	pub fn get_cache(&self, default: bool) -> bool {
		if let Some(fuse) = &self.fuse {
			if let Some(cache_directories) = fuse.cache_directories {
				return cache_directories;
			}
		}
		default
	}

	pub fn get_extension(&self) -> Option<String> {
		self.default.extension.clone()
	}

	pub fn get_secret_key(&self) -> Result<Vec<u8>> {
		let seckey_path = Path::new(&self.crypt4gh.seckey);
		log::info!("Loading secret key from {}", seckey_path.display());
		ensure!(seckey_path.is_file(), "Secret key not found");

		let callback: Box<dyn Fn() -> Result<String>> = match std::env::var(PASSPHRASE) {
			Ok(_) => {
				log::warn!("Warning: Using a passphrase in an environment variable is insecure");
				Box::new(|| {
					std::env::var(PASSPHRASE).map_err(|e| {
						anyhow!(
							"Unable to get the passphrase from the env variable C4GH_PASSPHRASE ({})",
							e
						)
					})
				})
			},
			Err(_) => Box::new(|| {
				read_password_from_tty(Some(format!("Passphrase for {}: ", seckey_path.display()).as_str()))
					.map_err(|e| anyhow!("Unable to read password from TTY: {}", e))
			}),
		};

		crypt4gh::keys::get_private_key(seckey_path, callback)
	}

	pub fn get_recipients(&self, seckey: &[u8]) -> HashSet<Keys> {
		let recipient_paths = &self.crypt4gh.recipient_keys.clone().unwrap_or(vec![]);

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
			let k = crypt4gh::keys::get_public_key_from_private_key(seckey).unwrap();
			recipient_pubkeys.insert(Keys {
				method: 0,
				privkey: seckey.to_vec(),
				recipient_pubkey: k,
			});
		}

		recipient_pubkeys
	}
}

impl FuseMountOption {
	pub fn to_os_string(&self) -> OsString {
		match self {
			FuseMountOption::FSName(name) => OsString::from(&format!("fsname={}", name)),
			FuseMountOption::Subtype(subtype) => OsString::from(&format!("subtype={}", subtype)),
			FuseMountOption::Custom(value) => OsString::from(&value.clone()),
			FuseMountOption::AllowOther => OsString::from("allow_other"),
			FuseMountOption::AllowRoot => OsString::from("allow_root"),
			FuseMountOption::AutoUnmount => OsString::from("auto_unmount"),
			FuseMountOption::DefaultPermissions => OsString::from("default_permissions"),
			FuseMountOption::Dev => OsString::from("dev"),
			FuseMountOption::NoDev => OsString::from("nodev"),
			FuseMountOption::Suid => OsString::from("suid"),
			FuseMountOption::NoSuid => OsString::from("nosuid"),
			FuseMountOption::Ro => OsString::from("ro"),
			FuseMountOption::Rw => OsString::from("rw"),
			FuseMountOption::Exec => OsString::from("exec"),
			FuseMountOption::NoExec => OsString::from("noexec"),
			FuseMountOption::Atime => OsString::from("atime"),
			FuseMountOption::NoAtime => OsString::from("noatime"),
			FuseMountOption::DirSync => OsString::from("dirsync"),
			FuseMountOption::Sync => OsString::from("sync"),
			FuseMountOption::Async => OsString::from("async"),
		}
	}
}

pub fn parse_config(mut config_file: File) -> Result<Config> {
	let mut config_string = String::new();
	config_file.read_to_string(&mut config_string)?;
	let config_toml = toml::from_str(config_string.as_str()).map_err(|e| anyhow!("Error reading config: {}", e));
	config_toml
}
