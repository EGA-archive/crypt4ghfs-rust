use std::env;
use std::fs::File;

use clap::{crate_authors, crate_version, load_yaml, App, AppSettings};
use crypt4ghfs::error::Crypt4GHFSError;
use crypt4ghfs::{config, run_with_config};

fn run() -> Result<(), Crypt4GHFSError> {
    // Init CLI
    let yaml = load_yaml!("../app.yaml");
    let matches = App::from(yaml)
        .version(crate_version!())
        .author(crate_authors!())
        .global_setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColorAlways)
        .global_setting(AppSettings::ColoredHelp)
        .get_matches();

    let mountpoint: String = matches.value_of_t("MOUNTPOINT")?;

    // Read config
    let config_path: String = matches.value_of_t("conf")?;
    log::info!("Loading config: {}", config_path);
    let config_file = File::open(config_path)?;

    let conf = config::Config::from_file(config_file)?;
    log::debug!("Config = {:?}", conf);

    // Run
    run_with_config(&conf, &mountpoint)
}

fn main() {
    if let Err(err) = run() {
        let _ = pretty_env_logger::try_init();
        log::error!("{}", err);
        std::process::exit(1);
    }
}
