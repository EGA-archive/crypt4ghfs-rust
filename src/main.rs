use clap::{crate_authors, crate_version, load_yaml, App, AppSettings};
use crypt4ghfs::{config, error::Crypt4GHFSError, run_with_config};
use std::os::unix::io::FromRawFd;
use std::{env, fs::File};

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
    let config_file = if matches.is_present("test") {
        File::open("tests/configs/fs.conf")?
    } else {
        let config_fh: i32 = matches.value_of_t("conf")?;
        log::info!("Loading config: {}", config_fh);
        unsafe { File::from_raw_fd(config_fh) }
    };
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
