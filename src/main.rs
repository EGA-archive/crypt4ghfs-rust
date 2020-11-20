use anyhow::Result;
use clap::{crate_authors, crate_version, load_yaml, App, AppSettings};
use pretty_env_logger;
use std::{env, ffi::OsStr, fs::File};

mod config;
mod fuse;

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
	let threads = matches.value_of_t("threads").unwrap_or(1);

	// Read config
	log::info!("Loading config: {}", config_path);
	let config_file = File::open(config_path).unwrap();
	let conf = config::parse_config(config_file).unwrap();
	let rootdir = conf.default.rootdir.clone();

	// Encryption / Decryption keys
	let seckey = conf.get_secret_key()?;
	let recipients = conf.get_recipients(&seckey);

	// Get options
	let options = conf
		.get_options(vec![
			config::FuseMountOption::Ro,
			config::FuseMountOption::DefaultPermissions,
			config::FuseMountOption::AutoUnmount,
		])
		.iter()
		.map(|option| option.to_os_string())
		.collect::<Vec<_>>();

	let options = options.iter().map(|os| OsStr::new(os)).collect();

	// Get cache
	let cache_directories = conf.get_cache(true);
	let extension = conf.get_extension();

	let fs = fuse::filesystem::Crypt4ghFS::new(rootdir, seckey, recipients, extension, cache_directories);
	fuse::run(fs, threads, mountpoint, foreground, options)?;
	Ok(())
}

fn main() {
	if let Err(err) = run() {
		log::error!("{}", err);
		std::process::exit(1);
	}
}
