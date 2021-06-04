use crate::error::Crypt4GHFSError;
use anyhow::anyhow;
use anyhow::Result;
use crypt4gh::Keys;
use itertools::Itertools;
use rpassword::read_password_from_tty;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    ffi::OsString,
    fs::File,
    io::Read,
    path::Path,
};

const PASSPHRASE: &str = "C4GH_PASSPHRASE";

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    #[serde(alias = "CRITICAL")]
    Critical,
    Warn,
    Info,
    Debug,
    #[serde(alias = "NOTSET")]
    Trace,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Facility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FuseMountOption {
    FSName(String),
    Subtype(String),
    Custom(String),
    AllowOther,
    AllowRoot,
    AutoUnmount,
    DefaultPermissions,
    Dev,
    NoDev,
    Suid,
    NoSuid,
    Ro,
    Rw,
    Exec,
    NoExec,
    Atime,
    NoAtime,
    DirSync,
    Sync,
    Async,
}

impl FuseMountOption {
    // TODO: Improve this
    pub fn to_os_string(&self) -> OsString {
        match self {
            Self::FSName(name) => OsString::from(&format!("-ofsname={}", name)),
            Self::Subtype(subtype) => OsString::from(&format!("-osubtype={}", subtype)),
            Self::Custom(value) => OsString::from(&value.clone()),
            Self::AllowOther => OsString::from("-oallow_other"),
            Self::AllowRoot => OsString::from("-oallow_root"),
            Self::AutoUnmount => OsString::from("-oauto_unmount"),
            Self::DefaultPermissions => OsString::from("-odefault_permissions"),
            Self::Dev => OsString::from("-odev"),
            Self::NoDev => OsString::from("-onodev"),
            Self::Suid => OsString::from("-osuid"),
            Self::NoSuid => OsString::from("-onosuid"),
            Self::Ro => OsString::from("-oro"),
            Self::Rw => OsString::from("-orw"),
            Self::Exec => OsString::from("-oexec"),
            Self::NoExec => OsString::from("-onoexec"),
            Self::Atime => OsString::from("-oatime"),
            Self::NoAtime => OsString::from("-onoatime"),
            Self::DirSync => OsString::from("-odirsync"),
            Self::Sync => OsString::from("-osync"),
            Self::Async => OsString::from("-oasync"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Default {
    extensions: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Fuse {
    options: Option<Vec<FuseMountOption>>,
    rootdir: String,
    cache_directories: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypt4GH {
    #[serde(rename = "seckey")]
    seckey_path: Option<String>,
    recipients: Option<Vec<String>>,
    include_myself_as_recipient: Option<bool>,
    include_crypt4gh_log: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Amqp {
    pub connection_url: String,
    pub exchange: String,
    pub routing_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoggerConfig {
    pub log_level: LogLevel,
    pub use_syslog: bool,
    pub log_facility: Option<Facility>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Config {
    default: Default,
    pub logger: LoggerConfig,
    fuse: Fuse,
    crypt4gh: Crypt4GH,
}

impl Config {
    pub fn new_with_defaults(rootdir: String, seckey_path: Option<String>) -> Self {
        Self {
            default: Default { extensions: vec![] },
            fuse: Fuse {
                rootdir,
                options: Some(vec![
                    FuseMountOption::Ro,
                    FuseMountOption::DefaultPermissions,
                    FuseMountOption::AutoUnmount,
                ]),
                cache_directories: Some(true),
            },
            crypt4gh: Crypt4GH {
                seckey_path,
                recipients: Some(vec![]),
                include_myself_as_recipient: Some(true),
                include_crypt4gh_log: Some(true),
            },
            logger: LoggerConfig {
                log_level: LogLevel::Info,
                use_syslog: false,
                log_facility: None,
            },
        }
    }

    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.default.extensions = extensions;
        self
    }

    pub const fn with_log_level(mut self, log_level: LogLevel) -> Self {
        self.logger.log_level = log_level;
        self
    }

    pub fn get_options(&self) -> Vec<FuseMountOption> {
        if let Some(options) = &self.fuse.options {
            return options.clone();
        }
        vec![FuseMountOption::Rw, FuseMountOption::DefaultPermissions]
    }

    pub const fn get_cache(&self) -> bool {
        if let Some(cache_directories) = self.fuse.cache_directories {
            return cache_directories;
        }
        true
    }

    pub fn get_extensions(&self) -> Vec<String> {
        self.default.extensions.clone()
    }

    pub fn get_secret_key(&self) -> Result<Option<Vec<u8>>, Crypt4GHFSError> {
        match &self.crypt4gh.seckey_path {
            Some(seckey_path_str) => {
                let seckey_path = Path::new(&seckey_path_str);
                log::info!("Loading secret key from {}", seckey_path.display());

                if !seckey_path.is_file() {
                    return Err(Crypt4GHFSError::SecretNotFound(seckey_path.into()));
                }

                let callback: Box<dyn Fn() -> Result<String>> = match std::env::var(PASSPHRASE) {
                    Ok(_) => {
                        log::warn!(
                            "Warning: Using a passphrase in an environment variable is insecure"
                        );
                        Box::new(|| {
                            std::env::var(PASSPHRASE).map_err(|e| {
                                anyhow!(
									"Unable to get the passphrase from the env variable C4GH_PASSPHRASE ({})",
									e
								)
                            })
                        })
                    }
                    Err(_) => Box::new(|| {
                        read_password_from_tty(Some(
                            format!("Passphrase for {}: ", seckey_path.display()).as_str(),
                        ))
                        .map_err(|e| anyhow!("Unable to read password from TTY: {}", e))
                    }),
                };

                let key = crypt4gh::keys::get_private_key(seckey_path, callback)
                    .map_err(|e| Crypt4GHFSError::SecretKeyError(e.to_string()))?;

                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    pub fn get_recipients(&self, seckey: &[u8]) -> HashSet<Keys> {
        let recipient_paths = &self.crypt4gh.recipients.clone().unwrap_or_default();

        let mut recipient_pubkeys: HashSet<_> = recipient_paths
            .iter()
            .map(Path::new)
            .filter(|path| path.exists())
            .filter_map(|path| {
                log::debug!("Recipient pubkey path: {}", path.display());
                crypt4gh::keys::get_public_key(path).ok()
            })
            .unique()
            .map(|key| Keys {
                method: 0,
                privkey: seckey.to_vec(),
                recipient_pubkey: key,
            })
            .collect();

        if self.crypt4gh.include_myself_as_recipient.unwrap_or(true) {
            let k = crypt4gh::keys::get_public_key_from_private_key(seckey)
                .expect("Unable to extract public key from seckey");
            recipient_pubkeys.insert(Keys {
                method: 0,
                privkey: seckey.to_vec(),
                recipient_pubkey: k,
            });
        }

        recipient_pubkeys
    }

    pub const fn get_log_level(&self) -> LogLevel {
        self.logger.log_level
    }

    pub fn get_rootdir(&self) -> String {
        self.fuse
            .rootdir
            .replace("{username}", &self.get_username())
    }

    #[allow(clippy::unused_self)]
    pub fn get_username(&self) -> String {
        whoami::username()
    }

    pub fn from_file(mut config_file: File) -> Result<Self, Crypt4GHFSError> {
        let mut config_string = String::new();
        config_file
            .read_to_string(&mut config_string)
            .map_err(|e| Crypt4GHFSError::BadConfig(e.to_string()))?;
        let config_toml = toml::from_str(config_string.as_str())
            .map_err(|e| Crypt4GHFSError::BadConfig(e.to_string()));
        config_toml
    }

    pub fn get_facility(&self) -> syslog::Facility {
        match self.logger.log_facility.unwrap_or(Facility::User) {
            Facility::Kern => syslog::Facility::LOG_KERN,
            Facility::User => syslog::Facility::LOG_USER,
            Facility::Mail => syslog::Facility::LOG_MAIL,
            Facility::Daemon => syslog::Facility::LOG_DAEMON,
            Facility::Auth => syslog::Facility::LOG_AUTH,
            Facility::Syslog => syslog::Facility::LOG_SYSLOG,
            Facility::Lpr => syslog::Facility::LOG_LPR,
            Facility::News => syslog::Facility::LOG_NEWS,
            Facility::Uucp => syslog::Facility::LOG_UUCP,
            Facility::Cron => syslog::Facility::LOG_CRON,
            Facility::Authpriv => syslog::Facility::LOG_AUTHPRIV,
            Facility::Ftp => syslog::Facility::LOG_FTP,
            Facility::Local0 => syslog::Facility::LOG_LOCAL0,
            Facility::Local1 => syslog::Facility::LOG_LOCAL1,
            Facility::Local2 => syslog::Facility::LOG_LOCAL2,
            Facility::Local3 => syslog::Facility::LOG_LOCAL3,
            Facility::Local4 => syslog::Facility::LOG_LOCAL4,
            Facility::Local5 => syslog::Facility::LOG_LOCAL5,
            Facility::Local6 => syslog::Facility::LOG_LOCAL6,
            Facility::Local7 => syslog::Facility::LOG_LOCAL7,
        }
    }

    pub fn setup_logger(&self) -> Result<(), Crypt4GHFSError> {
        let log_level: LogLevel = if let Ok(log_level_str) = std::env::var("RUST_LOG") {
            log_level_str
                .as_str()
                .try_into()
                .expect("Unable to parse RUST_LOG environment variable")
        } else {
            let log_level = self.get_log_level();
            let log_level_str = match log_level {
                LogLevel::Critical => "error",
                LogLevel::Warn => "warn",
                LogLevel::Info => "info",
                LogLevel::Debug => "debug",
                LogLevel::Trace => "trace",
            };
            std::env::set_var("RUST_LOG", log_level_str);
            log_level
        };

        // Choose logger
        if self.logger.use_syslog {
            syslog::init(self.get_facility(), log_level.into(), None)?;
        } else {
            let _ = pretty_env_logger::try_init(); // Ignore error
        }

        Ok(())
    }
}

impl TryFrom<&str> for LogLevel {
    type Error = Crypt4GHFSError;

    fn try_from(level: &str) -> Result<Self, Self::Error> {
        match level {
            "error" => Ok(Self::Critical),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(Crypt4GHFSError::BadConfig("Wrong log level".into())),
        }
    }
}

impl From<LogLevel> for log::LevelFilter {
    fn from(val: LogLevel) -> Self {
        match val {
            LogLevel::Critical => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace,
        }
    }
}
