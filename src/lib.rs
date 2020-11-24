use anyhow::{Result, ensure};
use config::Config;
use std::{ffi::OsStr, path::Path};

pub mod config;
mod fuse;

pub fn run_with_config(conf: Config, n_threads: usize, mountpoint: String, foreground: bool) -> Result<()> {
	// Init logger
	if std::env::var("RUST_LOG").is_err() {
		let log_level = match conf.get_log_level() {
			config::LogLevel::Error => "error",
			config::LogLevel::Warn => "warn",
			config::LogLevel::Info => "info",
			config::LogLevel::Debug => "debug",
			config::LogLevel::Trace => "trace",
		};
		std::env::set_var("RUST_LOG", log_level);
		pretty_env_logger::init();
	}

	let rootdir = conf.get_rootdir();
	ensure!(Path::new(&rootdir).exists(), "Rootdir doesn't exist (rootdir = {})", rootdir);

	// Encryption / Decryption keys
	let seckey = conf.get_secret_key()?;
	let recipients = conf.get_recipients(&seckey);

	// Get options
	let options = conf
		.get_options()
		.iter()
		.map(|option| option.to_os_string())
		.collect::<Vec<_>>();

	let options = options.iter().map(|os| OsStr::new(os)).collect();

	// Get cache
	let cache_directories = conf.get_cache();
	let extensions = conf.get_extensions();

	let fs = fuse::filesystem::Crypt4ghFS::new(rootdir, seckey, recipients, extensions, cache_directories);
	fuse::run(fs, n_threads, mountpoint, foreground, options)
}
