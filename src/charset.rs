//! Наборы символов для генерации паролей и расчёт энтропии.
//!
//! Это не криптографический примитив — просто данные и арифметика,
//! поэтому пишем сами, без внешних библиотек.

#[derive(Debug, Clone, Copy)]
pub struct CharsetOptions {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,

    /// Исключить визуально похожие символы (0/O, 1/l/I)
    /// для удобства ручного ввода.
    pub exclude_ambiguous: bool,
}

impl Default for CharsetOptions {
    fn default() -> Self {
        Self {
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}<>?/.,;:~";

const AMBIGUOUS: &str = "0O1lI|";

/// Собирает алфавит из выбранных опций.
///
/// Возвращает Vec<char> без дублей и в детерминированном порядке.
/// Порядок не имеет значения для безопасности: случайный выбор
/// выполняется в generator.rs.
pub fn build_charset(opts: CharsetOptions) -> Vec<char> {
    let mut alphabet = String::new();

    if opts.lower {
        alphabet.push_str(LOWER);
    }

    if opts.upper {
        alphabet.push_str(UPPER);
    }

    if opts.digits {
        alphabet.push_str(DIGITS);
    }

    if opts.symbols {
        alphabet.push_str(SYMBOLS);
    }

    let mut chars: Vec<char> = alphabet.chars().collect();

    if opts.exclude_ambiguous {
        chars.retain(|c| !AMBIGUOUS.contains(*c));
    }

    chars.sort_unstable();
    chars.dedup();

    chars
}

/// Энтропия пароля в битах.
///
/// Формула:
///
/// log2(alphabet_size) * length
///
/// Это максимальная теоретическая энтропия при условии,
/// что каждый символ выбирается независимо и равновероятно.
pub fn entropy_bits(alphabet_len: usize, length: usize) -> f64 {
    if alphabet_len == 0 || length == 0 {
        return 0.0;
    }

    (alphabet_len as f64).log2() * (length as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_charset_has_expected_number_of_symbols() {
        let chars = build_charset(CharsetOptions::default());

        // 26 lowercase
        // + 26 uppercase
        // + 10 digits
        // + 27 symbols
        // = 89 unique characters.
        assert_eq!(chars.len(), 89);

        let mut sorted = chars.clone();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(
            chars.len(),
            sorted.len(),
            "charset must not contain duplicates"
        );
    }

    #[test]
    fn exclude_ambiguous_removes_confusing_chars() {
        let opts = CharsetOptions {
            exclude_ambiguous: true,
            ..Default::default()
        };

        let chars = build_charset(opts);

        for c in AMBIGUOUS.chars() {
            assert!(
                !chars.contains(&c),
                "ambiguous char {c} should be excluded"
            );
        }
    }

    #[test]
    fn entropy_matches_known_values() {
        // log2(89) * 20 ≈ 129.66 bits.
        let e = entropy_bits(89, 20);

        assert!(
            (e - 129.66).abs() < 0.01,
            "unexpected entropy: {e}"
        );
    }

    #[test]
    fn empty_charset_has_zero_entropy() {
        assert_eq!(entropy_bits(0, 20), 0.0);
    }

    #[test]
    fn zero_length_has_zero_entropy() {
        assert_eq!(entropy_bits(89, 0), 0.0);
    }

    #[test]
    fn charset_options_work_independently() {
        let lower = build_charset(CharsetOptions {
            lower: true,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        });

        assert_eq!(lower.len(), 26);

        let upper = build_charset(CharsetOptions {
            lower: false,
            upper: true,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        });

        assert_eq!(upper.len(), 26);

        let digits = build_charset(CharsetOptions {
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        });

        assert_eq!(digits.len(), 10);
    }
}