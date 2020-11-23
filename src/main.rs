use anyhow::Result;
use clap::{crate_authors, crate_version, load_yaml, App, AppSettings};
use crypt4ghfs::{config, run_with_config};
use pretty_env_logger;
use std::{env, fs::File};

fn run() -> Result<()> {
	// Init CLI
	let yaml = load_yaml!("../app.yaml");
	let matches = App::from(yaml)
		.version(crate_version!())
		.author(crate_authors!())
		.global_setting(AppSettings::ArgRequiredElseHelp)
		.global_setting(AppSettings::ColorAlways)
		.global_setting(AppSettings::ColoredHelp)
		.get_matches();

	// Init logger
	if std::env::var("RUST_LOG").is_err() {
		if matches.is_present("verbose") {
			std::env::set_var("RUST_LOG", "trace");
		}
		else {
			std::env::set_var("RUST_LOG", "info");
		}
	}

	pretty_env_logger::init();

	// Read args
	let config_path = matches.value_of("conf").unwrap();
	let mountpoint = matches.value_of_t("MOUNTPOINT").expect("No mountpoint");
	let foreground = matches.is_present("foreground");
	let n_threads = matches.value_of_t("threads").unwrap_or(1);

	// Read config
	log::info!("Loading config: {}", config_path);
	let config_file = File::open(config_path).unwrap();
	let conf = config::Config::from_file(config_file).unwrap();

	run_with_config(conf, n_threads, mountpoint, foreground)
}

fn main() {
	if let Err(err) = run() {
		log::error!("{}", err);
		std::process::exit(1);
	}
}
