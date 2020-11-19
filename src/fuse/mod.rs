use anyhow::anyhow;
use anyhow::Result;
use filesystem::Crypt4ghFS;
use std::ffi::OsStr;

pub mod filesystem;
pub mod libc_wrappers;
pub mod libc_extras;

pub fn run(fs: Crypt4ghFS, threads: usize, mountpoint: String, foreground: bool, options: Vec<&OsStr>) -> Result<()> {
	fuse_mt::mount(fuse_mt::FuseMT::new(fs, threads), &mountpoint, &options).map_err(|e| anyhow!("{:?}", e))
}
