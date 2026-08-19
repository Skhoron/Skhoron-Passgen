//! Генерация пароля через rejection sampling.
//!
//! Источник случайности — OsRng (crate `rand`), библиотечный, не наш —
//! это единственный компонент здесь, который категорически нельзя писать
//! самому (см. обсуждение DUAL_EC_DRBG и почему RNG — не место для
//! творчества). Сам алгоритм отбора символов из алфавита — наш код.
//!
//! ## Почему не `OsRng.next_u32() % alphabet.len()`
//!
//! Наивный modulo даёт смещённое распределение, если `alphabet.len()` не
//! делит 2^32 нацело. Пример: alphabet.len() = 94, 2^32 % 94 = 60 — то
//! есть первые 60 символов алфавита выбираются чуть чаще, чем остальные.
//! Смещение небольшое на глаз, но оно снижает РЕАЛЬНУЮ энтропию пароля
//! ниже теоретической log2(94)*length, и это измеримо.
//!
//! ## Rejection sampling
//!
//! Вычисляем `limit = u32::MAX - (u32::MAX % n)` — наибольшее число,
//! кратное `n`, не превышающее диапазон u32. Значения `>= limit`
//! отбрасываются и генерируются заново. Оставшийся диапазон `[0, limit)`
//! делится на `n` без остатка → `val % n` даёт строго равномерное
//! распределение по индексам алфавита.

use crate::charset::CharsetOptions;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum GeneratorError {
    #[error("password length must be > 0")]
    ZeroLength,
    #[error("charset is empty after applying options — enable at least one character class")]
    EmptyCharset,
}

/// Генерирует пароль длины `length` из алфавита, построенного по `opts`.
/// Каждый символ выбирается независимо через rejection sampling — без
/// modulo bias, реальная энтропия равна теоретической
/// `charset::entropy_bits(alphabet.len(), length)`.
pub fn generate_password(length: usize, opts: CharsetOptions) -> Result<String, GeneratorError> {
    if length == 0 {
        return Err(GeneratorError::ZeroLength);
    }

    let alphabet = crate::charset::build_charset(opts);
    if alphabet.is_empty() {
        return Err(GeneratorError::EmptyCharset);
    }

    let n = alphabet.len() as u32;
    let limit = u32::MAX - (u32::MAX % n);

    let mut password = String::with_capacity(length);
    let mut rng = OsRng;

    while password.len() < length {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let val = u32::from_le_bytes(buf);
        buf.zeroize();

        if val >= limit {
            continue; // rejection: отбрасываем смещённый "хвост" диапазона
        }
        let idx = (val % n) as usize;
        password.push(alphabet[idx]);
    }

    Ok(password)
}

/// Генерирует несколько независимых паролей-кандидатов, чтобы можно было
/// выбрать один — сама генерация каждого не менее стойкая, это просто
/// удобство выбора (как в менеджерах паролей "предложить варианты").
pub fn generate_candidates(
    count: usize,
    length: usize,
    opts: CharsetOptions,
) -> Result<Vec<String>, GeneratorError> {
    (0..count).map(|_| generate_password(length, opts)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charset::CharsetOptions;

    #[test]
    fn generates_password_of_correct_length() {
        let pw = generate_password(20, CharsetOptions::default()).unwrap();
        assert_eq!(pw.chars().count(), 20);
    }

    #[test]
    fn rejects_zero_length() {
        assert!(matches!(
            generate_password(0, CharsetOptions::default()),
            Err(GeneratorError::ZeroLength)
        ));
    }

    #[test]
    fn rejects_empty_charset() {
        let opts = CharsetOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(matches!(
            generate_password(10, opts),
            Err(GeneratorError::EmptyCharset)
        ));
    }

    #[test]
    fn two_generated_passwords_differ() {
        let a = generate_password(32, CharsetOptions::default()).unwrap();
        let b = generate_password(32, CharsetOptions::default()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn distribution_is_reasonably_uniform_across_alphabet() {
        // Статистическая проверка (не формальное доказательство): при
        // достаточно большой выборке частоты символов не должны сильно
        // отклоняться от равномерных. Ловит грубые ошибки вроде
        // забытого rejection sampling (наивный modulo дал бы заметный
        // перекос для алфавита размером 94 на диапазоне u32).
        let opts = CharsetOptions::default();
        let alphabet = crate::charset::build_charset(opts);
        let long_password = generate_password(50_000, opts).unwrap();

        let mut counts = std::collections::HashMap::new();
        for c in long_password.chars() {
            *counts.entry(c).or_insert(0u32) += 1;
        }

        let expected = 50_000.0 / alphabet.len() as f64;
        for &count in counts.values() {
            let deviation = (count as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.25,
                "character frequency deviates too much from uniform: {count} vs expected ~{expected:.0}"
            );
        }
    }
}