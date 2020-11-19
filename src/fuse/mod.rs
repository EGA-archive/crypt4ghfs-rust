use anyhow::anyhow;
use anyhow::Result;
use filesystem::Crypt4ghFS;
use std::ffi::OsStr;
use fork::{daemon, Fork};

pub mod filesystem;
pub mod libc_wrappers;
pub mod libc_extras;

pub fn run(fs: Crypt4ghFS, threads: usize, mountpoint: String, foreground: bool, options: Vec<&OsStr>) -> Result<()> {
	if foreground {
		fuse_mt::mount(fuse_mt::FuseMT::new(fs, threads), &mountpoint, &options).map_err(|e| anyhow!("{:?}", e)).unwrap();
	}
	else {
		if let Ok(Fork::Child) = daemon(true, true) {
			fuse_mt::mount(fuse_mt::FuseMT::new(fs, threads), &mountpoint, &options).map_err(|e| anyhow!("{:?}", e)).unwrap();
		}
	}
	Ok(())
}
