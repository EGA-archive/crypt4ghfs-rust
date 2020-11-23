use anyhow::Result;
use anyhow::{anyhow, ensure};
use filesystem::Crypt4ghFS;
use fork::{fork, Fork};
use std::ffi::OsStr;

pub mod filesystem;
pub mod libc_extras;
pub mod libc_wrappers;

pub fn run(fs: Crypt4ghFS, n_threads: usize, mountpoint: String, foreground: bool, options: Vec<&OsStr>) -> Result<()> {
	if foreground {
		ensure!(
			std::path::Path::new(&mountpoint).exists(),
			"Unable to access mountpoint ({})",
			mountpoint
		);
		fuse_mt::mount(fuse_mt::FuseMT::new(fs, n_threads), &mountpoint, &options).map_err(|e| anyhow!("{:?}", e))
	}
	else {
		log::info!("Spawning daemon");
		match fork() {
			Ok(Fork::Child) => {
				fuse_mt::mount(fuse_mt::FuseMT::new(fs, n_threads), &mountpoint, &options)
					.map_err(|e| anyhow!("{:?}", e))?;
				std::process::exit(0);
			},
			Ok(Fork::Parent(_)) => Ok(()),
			Err(_) => Err(anyhow!("Fork failed")),
		}
	}
}
