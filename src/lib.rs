#![allow(
	clippy::upper_case_acronyms,
	clippy::missing_panics_doc,
	clippy::missing_errors_doc,
	clippy::must_use_candidate,
	clippy::module_name_repetitions,
	clippy::cast_sign_loss,
	clippy::cast_possible_truncation,
	clippy::similar_names
)]

use std::path::{Path, PathBuf};

use config::Config;
use error::Crypt4GHFSError;

pub mod config;
mod directory;
mod egafile;
mod encrypted_file;
pub mod error;
mod file_admin;
mod filesystem;
mod regular_file;
mod utils;

pub fn run_with_config(conf: &Config, mountpoint: PathBuf) -> Result<(), Crypt4GHFSError> {
	// Set log level and logger
	conf.setup_logger()?;

	let rootdir = conf.get_rootdir();
	if !Path::new(&rootdir).exists() {
		return Err(Crypt4GHFSError::PathDoesNotExist(Path::new(&rootdir).into()));
	}

	// Encryption / Decryption keys
	let seckey = (conf.get_secret_key()?).map_or_else(
		|| {
			log::warn!("No seckey specified");
			vec![0_u8; 32]
		},
		|key| key,
	);

	let recipients = conf.get_recipients(&seckey);

	// Get options
	let options = conf.get_options();

	let fs = filesystem::Crypt4ghFS::new(
		&rootdir,
		seckey,
		recipients,
		nix::unistd::getuid(),
		nix::unistd::getgid(),
	);

	if !mountpoint.exists() {
		return Err(Crypt4GHFSError::PathDoesNotExist(mountpoint));
	}

	fuser::mount2(fs, &mountpoint, &options).map_err(|e| Crypt4GHFSError::MountError(e.to_string()))
}
