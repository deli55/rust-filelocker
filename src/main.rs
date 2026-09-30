use arboard::Clipboard;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;

use rust_filelocker::vault::{self, VaultError};

/// rust-filelocker: A secure file locking/unlocking tool
#[derive(Parser, Debug)]
#[command(name = "rust-filelocker")]
#[command(about = "Encrypt, lock, and manage files securely", long_about = None)]
struct Cli {
    /// Optional global verbosity flag
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Lock a file or directory
    Lock {
        /// Target file or path to lock
        #[arg(short, long)]
        input: PathBuf,

        /// Output location for the locked container
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Unlock a locked container
    Unlock {
        /// Path to the .lock file
        #[arg(short, long)]
        input: PathBuf,

        /// Destination output directory for unlocked files
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List stored keys/metadata in a lock container
    List {
        /// Path to the .lock file to inspect
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Set a secret in a secrets vault
    Set {
        /// Path to the secrets vault (.lock file)
        #[arg(short, long)]
        vault: PathBuf,

        /// Secret key name
        #[arg(short, long)]
        key: String,

        /// Secret value (omitted to prompt for it securely)
        #[arg(short, long)]
        value: Option<String>,
    },

    /// Get a secret from a secrets vault
    Get {
        /// Path to the secrets vault (.lock file)
        #[arg(short, long)]
        vault: PathBuf,

        /// Secret key name to retrieve
        #[arg(short, long)]
        key: String,

        /// Copy the secret to clipboard instead of printing
        #[arg(long)]
        clip: bool,
    },

    /// Remove a secret from a secrets vault
    Remove {
        /// Path to the secrets vault (.lock file)
        #[arg(short, long)]
        vault: PathBuf,

        /// Secret key name to remove
        #[arg(short, long)]
        key: String,
    },

    /// Import secrets from a .env file into a secrets vault
    ImportEnv {
        /// Path to the .env file to import
        #[arg(short, long)]
        env: PathBuf,

        /// Path to the secrets vault (.lock file)
        #[arg(short, long)]
        vault: PathBuf,
    },

    /// Export secrets from a secrets vault to a .env file
    ExportEnv {
        /// Path to the secrets vault (.lock file)
        #[arg(short, long)]
        vault: PathBuf,

        /// Path to the output .env file
        #[arg(short, long)]
        env: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = run(cli);

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), VaultError> {
    match cli.command {
        Commands::Lock { input, output } => {
            let password = match vault::prompt_password_with_confirmation() {
                Ok(p) => Zeroizing::new(p),
                Err(VaultError::PasswordMismatch) => {
                    eprintln!("Error: Passwords do not match.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            vault::lock_file(&input, &output, &password)
        }
        Commands::Unlock { input, output } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            vault::unlock_file(&input, &output, &password)
        }
        Commands::List { input } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            vault::list_contents(&input, &password)
        }
        Commands::Set { vault, key, value } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let secret_value = match value {
                Some(v) => Zeroizing::new(v),
                None => {
                    print!("Enter secret value: ");
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    match rpassword::read_password() {
                        Ok(val) => Zeroizing::new(val),
                        Err(e) => {
                            eprintln!("Error reading secret: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            };

            vault::set_secret(&vault, &key, &secret_value, &password)
        }
        Commands::Get { vault, key, clip } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            match vault::get_secret_zeroizing(&vault, &key, &password) {
                Ok(Some(secret)) => {
                    if clip {
                        match Clipboard::new() {
                            Ok(mut cb) => match cb.set_text(&*secret) {
                                Ok(_) => println!("Secret '{}' copied to clipboard.", key),
                                Err(e) => {
                                    eprintln!("Failed to copy to clipboard: {}", e);
                                    eprintln!("Secret value: {}", *secret);
                                }
                            },
                            Err(e) => {
                                eprintln!("Failed to open clipboard: {}", e);
                                eprintln!("Secret value: {}", *secret);
                            }
                        }
                    } else {
                        println!("{}", *secret);
                    }
                    Ok(())
                }
                Ok(None) => {
                    eprintln!("Secret not found: {}", key);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Remove { vault, key } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            match vault::remove_secret(&vault, &key, &password) {
                Ok(true) => Ok(()),
                Ok(false) => {
                    eprintln!("Secret '{}' not found.", key);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::ImportEnv {
            env: env_path,
            vault,
        } => {
            let password = match vault::prompt_password_with_confirmation() {
                Ok(p) => Zeroizing::new(p),
                Err(VaultError::PasswordMismatch) => {
                    eprintln!("Error: Passwords do not match.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            vault::import_env(&env_path, &vault, &password)
        }
        Commands::ExportEnv {
            vault,
            env: env_path,
        } => {
            let password = match vault::prompt_password() {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            vault::export_env(&vault, &env_path, &password)
        }
    }
}
