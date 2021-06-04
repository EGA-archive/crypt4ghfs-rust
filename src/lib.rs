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

use config::Config;
use error::Crypt4GHFSError;
use std::{ffi::OsStr, path::Path};

mod checksum;
pub mod config;
mod directory;
mod egafile;
mod encrypted_file;
pub mod error;
mod file_admin;
mod filesystem;
mod inbox;
mod regular_file;
mod utils;

pub fn run_with_config(conf: &Config, mountpoint: &str) -> Result<(), Crypt4GHFSError> {
    // Set log level and logger
    conf.setup_logger()?;

    let rootdir = conf.get_rootdir();
    if !Path::new(&rootdir).exists() {
        return Err(Crypt4GHFSError::PathDoesNotExist(
            Path::new(&rootdir).into(),
        ));
    }

    // Encryption / Decryption keys
    let seckey = if let Some(key) = conf.get_secret_key()? {
        key
    } else {
        log::warn!("No seckey specified");
        vec![0_u8; 32]
    };

    let recipients = conf.get_recipients(&seckey);

    // Get options
    let options = conf
        .get_options()
        .iter()
        .map(config::FuseMountOption::to_os_string)
        .collect::<Vec<_>>();

    let options = options.iter().map(|os| OsStr::new(os)).collect::<Vec<_>>();

    let mountpoint = mountpoint.replace("<username>", &conf.get_username());

    let fs = filesystem::Crypt4ghFS::new(
        &rootdir,
        seckey,
        recipients,
        nix::unistd::getuid(),
        nix::unistd::getgid(),
    );

    if !Path::new(&mountpoint).exists() {
        return Err(Crypt4GHFSError::PathDoesNotExist(
            Path::new(&mountpoint).into(),
        ));
    }

    fuser::mount(fs, &mountpoint, &options).map_err(|e| Crypt4GHFSError::MountError(e.to_string()))
}
