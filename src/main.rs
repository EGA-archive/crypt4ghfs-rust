use std::fs::File;

use clap::StructOpt;
use crypt4ghfs::error::Crypt4GHFSError;
use crypt4ghfs::{config, run_with_config};

use crate::cli::Args;

mod cli;

fn run() -> Result<(), Crypt4GHFSError> {
	// Init CLI
	let matches = Args::parse();

	let mountpoint = matches.mountpoint;

	// Read config
	let config_path = matches.conf;
	log::info!("Loading config: {:?}", config_path);
	let config_file = File::open(config_path)?;

	let conf = config::Config::from_file(config_file)?;
	log::debug!("Config = {:?}", conf);

	// Run
	run_with_config(&conf, mountpoint)
}

fn main() {
	if let Err(err) = run() {
		let _ = pretty_env_logger::try_init();
		log::error!("{}", err);
		std::process::exit(1);
	}
}
