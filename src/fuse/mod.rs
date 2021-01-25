use crate::error::Crypt4GHFSError;
use filesystem::Crypt4ghFS;
use fork::{fork, Fork};
use std::{ffi::OsStr, path::Path};

pub mod filesystem;
pub mod libc_extras;
pub mod libc_wrappers;

pub fn run(
	fs: Crypt4ghFS,
	n_threads: usize,
	mountpoint: String,
	foreground: bool,
	options: Vec<&OsStr>,
) -> Result<(), Crypt4GHFSError> {
	if foreground {
		if !Path::new(&mountpoint).exists() {
			return Err(Crypt4GHFSError::PathDoesNotExist(Path::new(&mountpoint).into()));
		}
		fuse_mt::mount(fuse_mt::FuseMT::new(fs, n_threads), &mountpoint, &options)
			.map_err(|e| Crypt4GHFSError::MountError(e.to_string()))
	}
	else {
		log::info!("Spawning daemon");
		match fork() {
			Ok(Fork::Child) => {
				fuse_mt::mount(fuse_mt::FuseMT::new(fs, n_threads), &mountpoint, &options)
					.map_err(|e| Crypt4GHFSError::MountError(e.to_string()))?;
				std::process::exit(0);
			},
			Ok(Fork::Parent(_)) => Ok(()),
			Err(_) => Err(Crypt4GHFSError::ForkFailed),
		}
	}
}
