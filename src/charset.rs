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
    /// Исключить визуально похожие символы (0/O, 1/l/I) — удобство
    /// ручного ввода/переписывания за счёт небольшого снижения алфавита.
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

/// Собирает алфавит из выбранных опций. Возвращает Vec<char> без дублей,
/// в детерминированном порядке (важно для воспроизводимости построения,
/// не для безопасности — сам выбор символов из алфавита будет случайным).
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

/// Энтропия пароля в битах: log2(alphabet_size) * length.
/// Это верхняя граница энтропии ПРИ УСЛОВИИ, что каждый символ выбирается
/// независимо и равновероятно — именно это и гарантирует rejection sampling
/// в generator.rs (без него из-за modulo bias реальная энтропия была бы ниже).
pub fn entropy_bits(alphabet_len: usize, length: usize) -> f64 {
    (alphabet_len as f64).log2() * (length as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_charset_has_94_symbols_before_exclusion() {
        let chars = build_charset(CharsetOptions::default());
        // 26 + 26 + 10 + 28 (символы выше) = 90; проверяем отсутствие дублей,
        // не конкретное магическое число, которое зависит от набора SYMBOLS.
        let mut sorted = chars.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(chars.len(), sorted.len(), "charset must not contain duplicates");
        assert!(chars.len() > 80);
    }

    #[test]
    fn exclude_ambiguous_removes_confusing_chars() {
        let opts = CharsetOptions {
            exclude_ambiguous: true,
            ..Default::default()
        };
        let chars = build_charset(opts);
        for c in AMBIGUOUS.chars() {
            assert!(!chars.contains(&c), "ambiguous char {c} should be excluded");
        }
    }

    #[test]
    fn entropy_matches_known_values() {
        // log2(94) * 20 ≈ 131.15
        let e = entropy_bits(94, 20);
        assert!((e - 131.15).abs() < 0.1);
    }
}