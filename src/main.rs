//! Skhoron-Passgen — CLI: генерация паролей + хеширование + проверка.
//!
//! Хранилище содержит только Argon2id-хеши, а не сами пароли.
//! Сгенерированный пароль показывается один раз после успешного
//! сохранения его хеша.

mod charset;
mod generator;
mod hasher;
mod store;

use charset::CharsetOptions;
use clap::{Parser, Subcommand};
use hasher::PasswordHasherWrapper;
use std::io::{self, Write};
use std::path::PathBuf;
use store::PasswordStore;
use zeroize::Zeroize;

const MAX_PASSWORD_LENGTH: usize = 4096;

#[derive(Parser)]
#[command(
    name = "skhoron-passgen",
    about = "Генератор паролей с хешированием (Argon2id)"
)]
struct Cli {
    /// Путь к файлу хранилища хешей.
    #[arg(long, default_value = "skhoron-passgen-store.txt")]
    store: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Сгенерировать пароль и вывести его без сохранения.
    Generate {
        /// Длина пароля: от 1 до 4096 символов.
        #[arg(
            short,
            long,
            default_value_t = 20,
            value_parser = clap::value_parser!(usize).range(1..=MAX_PASSWORD_LENGTH)
        )]
        length: usize,

        /// Количество паролей: минимум 1.
        #[arg(
            long,
            default_value_t = 1,
            value_parser = clap::value_parser!(usize).range(1..)
        )]
        count: usize,

        /// Не использовать специальные символы.
        #[arg(long)]
        no_symbols: bool,

        /// Исключить визуально похожие символы: 0/O/1/l/I.
        #[arg(long)]
        exclude_ambiguous: bool,
    },

    /// Сгенерировать пароль и сохранить его Argon2id-хеш.
    New {
        /// Название записи.
        label: String,

        /// Длина пароля: от 1 до 4096 символов.
        #[arg(
            short,
            long,
            default_value_t = 20,
            value_parser = clap::value_parser!(usize).range(1..=MAX_PASSWORD_LENGTH)
        )]
        length: usize,

        /// Не использовать специальные символы.
        #[arg(long)]
        no_symbols: bool,

        /// Исключить визуально похожие символы: 0/O/1/l/I.
        #[arg(long)]
        exclude_ambiguous: bool,
    },

    /// Проверить введённый пароль против сохранённого хеша.
    Verify {
        /// Название записи.
        label: String,
    },

    /// Показать список сохранённых меток.
    List,

    /// Удалить запись из хранилища.
    Remove {
        /// Название записи.
        label: String,
    },
}

/// Безопасно читает пароль без отображения символов.
fn read_password_hidden(prompt: &str) -> Result<String, io::Error> {
    print!("{prompt}");
    io::stdout().flush()?;

    rpassword::read_password()
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

            let entropy = charset::entropy_bits(
                alphabet_len,
                length,
            );

            match generator::generate_candidates(
                count,
                length,
                opts,
            ) {
                Ok(passwords) => {
                    for password in &passwords {
                        println!("{password}");
                    }

                    eprintln!(
                        "\nЭнтропия одного пароля: \
                         ~{entropy:.1} бит \
                         (алфавит: {alphabet_len} символов)"
                    );
                }

                Err(error) => {
                    eprintln!("Ошибка генерации: {error}");
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

            // Сначала генерируем пароль.
            let mut password =
                match generator::generate_password(length, opts) {
                    Ok(password) => password,

                    Err(error) => {
                        eprintln!("Ошибка генерации: {error}");
                        std::process::exit(1);
                    }
                };

            // Затем создаём Argon2id-хеш.
            let hasher =
                PasswordHasherWrapper::default_params();

            let phc_hash = match hasher.hash(&password) {
                Ok(hash) => hash,

                Err(error) => {
                    eprintln!("Ошибка хеширования: {error}");
                    password.zeroize();
                    std::process::exit(1);
                }
            };

            // Открываем хранилище.
            let mut store =
                match PasswordStore::load_or_create(&cli.store) {
                    Ok(store) => store,

                    Err(error) => {
                        eprintln!(
                            "Ошибка открытия хранилища: {error}"
                        );

                        password.zeroize();
                        std::process::exit(1);
                    }
                };

            // Сначала обязательно сохраняем хеш.
            //
            // Если сохранение не удалось, пароль НЕ показываем.
            match store.add(&label, &phc_hash) {
                Ok(()) => {
                    println!(
                        "Хеш успешно сохранён под меткой {label:?}."
                    );

                    println!(
                        "\nСгенерированный пароль \
                         (сохраните его сейчас):"
                    );

                    println!("{password}");

                    println!(
                        "\nФайл хранилища: {:?}",
                        cli.store
                    );

                    println!(
                        "\nВнимание: пароль показывается \
                         только один раз."
                    );

                    // После вывода очищаем пароль из памяти.
                    password.zeroize();
                }

                Err(error) => {
                    eprintln!("Ошибка сохранения: {error}");

                    password.zeroize();

                    std::process::exit(1);
                }
            }
        }

        Command::Verify { label } => {
            let store =
                match PasswordStore::load_or_create(&cli.store) {
                    Ok(store) => store,

                    Err(error) => {
                        eprintln!(
                            "Ошибка открытия хранилища: {error}"
                        );

                        std::process::exit(1);
                    }
                };

            let stored_hash = match store.get(&label) {
                Ok(hash) => hash,

                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            };

            let mut entered =
                match read_password_hidden(
                    "Введите пароль для проверки: ",
                ) {
                    Ok(password) => password,

                    Err(error) => {
                        eprintln!(
                            "Ошибка чтения пароля: {error}"
                        );

                        std::process::exit(1);
                    }
                };

            let hasher =
                PasswordHasherWrapper::default_params();

            let result =
                hasher.verify(&entered, stored_hash);

            // Очищаем введённый пароль после проверки.
            entered.zeroize();

            match result {
                Ok(true) => {
                    println!("\n✅ Пароль верный");
                }

                Ok(false) => {
                    println!("\n❌ Пароль неверный");
                    std::process::exit(1);
                }

                Err(error) => {
                    eprintln!("Ошибка проверки: {error}");
                    std::process::exit(1);
                }
            }
        }

        Command::List => {
            let store =
                match PasswordStore::load_or_create(&cli.store) {
                    Ok(store) => store,

                    Err(error) => {
                        eprintln!(
                            "Ошибка открытия хранилища: {error}"
                        );

                        std::process::exit(1);
                    }
                };

            let labels = store.list_labels();

            if labels.is_empty() {
                println!("Хранилище пустое.");
            } else {
                for label in labels {
                    println!("{label}");
                }
            }
        }

        Command::Remove { label } => {
            let mut store =
                match PasswordStore::load_or_create(&cli.store) {
                    Ok(store) => store,

                    Err(error) => {
                        eprintln!(
                            "Ошибка открытия хранилища: {error}"
                        );

                        std::process::exit(1);
                    }
                };

            match store.remove(&label) {
                Ok(()) => {
                    println!(
                        "Метка {label:?} успешно удалена."
                    );
                }

                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
    }
}