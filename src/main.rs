//! Skhoron-Passgen — CLI: генерация паролей + хеширование + проверка.
//!
//! ⚠️ Хранит только Argon2id-хеши сгенерированных паролей (для проверки
//! "тот ли это пароль" — как мастер-пароль), НЕ сами пароли.
//! Сам сгенерированный пароль показывается один раз в терминале — его
//! нужно самостоятельно сохранить.

mod charset;
mod generator;
mod hasher;
mod store;

use charset::CharsetOptions;
use clap::{Parser, Subcommand};
use hasher::PasswordHasherWrapper;
use std::path::PathBuf;
use store::PasswordStore;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "skhoron-passgen", about = "Генератор паролей с хешированием (Argon2id)")]
struct Cli {
    /// Путь к файлу хранилища хешей.
    #[arg(long, default_value = "skhoron-passgen-store.txt")]
    store: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Сгенерировать пароль и вывести его (без сохранения).
    Generate {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Сгенерировать пароль, показать его один раз и сохранить его
    /// Argon2id-хеш под меткой `label` для последующей проверки.
    New {
        label: String,
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Проверить введённый пароль против сохранённого хеша по метке.
    Verify { label: String },
    /// Показать список меток в хранилище.
    List,
    /// Удалить метку из хранилища.
    Remove { label: String },
}

fn read_password_hidden(prompt: &str) -> String {
    print!("{prompt}");
    use std::io::Write;
    std::io::stdout().flush().ok();
    rpassword::read_password().unwrap_or_default()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            length,
            count,
            no_symbols,
            exclude_ambiguous,
        } => {
            let opts = CharsetOptions {
                symbols: !no_symbols,
                exclude_ambiguous,
                ..Default::default()
            };
            let alphabet_len = charset::build_charset(opts).len();
            let entropy = charset::entropy_bits(alphabet_len, length);

            match generator::generate_candidates(count, length, opts) {
                Ok(passwords) => {
                    for pw in &passwords {
                        println!("{pw}");
                    }
                    eprintln!("\nЭнтропия: ~{entropy:.1} бит (алфавит: {alphabet_len} символов)");
                }
                Err(e) => {
                    eprintln!("Ошибка генерации: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::New {
            label,
            length,
            no_symbols,
            exclude_ambiguous,
        } => {
            let opts = CharsetOptions {
                symbols: !no_symbols,
                exclude_ambiguous,
                ..Default::default()
            };

            let mut password = match generator::generate_password(length, opts) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Ошибка генерации: {e}");
                    std::process::exit(1);
                }
            };

            println!("Сгенерированный пароль (сохраните его сейчас, он больше не будет показан):");
            println!("{password}");

            let hasher = PasswordHasherWrapper::default_params();
            let phc_hash = match hasher.hash(&password) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Ошибка хеширования: {e}");
                    password.zeroize();
                    std::process::exit(1);
                }
            };
            password.zeroize();

            let mut store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };

            match store.add(&label, &phc_hash) {
                Ok(()) => println!("\nХеш сохранён под меткой {label:?} в {:?}", cli.store),
                Err(e) => {
                    eprintln!("Ошибка сохранения: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Verify { label } => {
            let store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };

            let stored_hash = match store.get(&label) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            let mut entered = read_password_hidden("Введите пароль для проверки: ");
            let hasher = PasswordHasherWrapper::default_params();
            let result = hasher.verify(&entered, stored_hash);
            entered.zeroize();

            match result {
                Ok(true) => println!("\n✅ Пароль верный"),
                Ok(false) => {
                    println!("\n❌ Пароль неверный");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Ошибка проверки: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::List => {
            let store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };
            for label in store.list_labels() {
                println!("{label}");
            }
        }

        Command::Remove { label } => {
            let mut store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };
            match store.remove(&label) {
                Ok(()) => println!("Метка {label:?} удалена"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
    }
}