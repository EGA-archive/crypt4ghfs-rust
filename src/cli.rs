use std::path::PathBuf;

/// Fuse layer exposing Crypt4GH-encrypted files, as if they were decrypted.
#[derive(clap::Parser)]
#[clap(about, version, author)]
pub struct Args {
	/// Display debug information
	#[clap(short, long)]
	pub verbose: bool,

	/// Path to the config file
	#[clap(short, long)]
	pub conf: PathBuf,

	/// Path to the mountpoint
	#[clap()]
	pub mountpoint: PathBuf,
}
