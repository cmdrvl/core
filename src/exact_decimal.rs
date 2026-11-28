//! Bounded exact decimal values for original JSON number tokens.
//!
//! ExactDecimal deliberately does not use serde_json::Number: the default
//! representation may already have rounded a token through f64, while the
//! arbitrary_precision feature changes serde_json::Value semantics for an
//! entire consumer graph. Callers that still have the source token can parse
//! it here and choose the semantic or presentation form they need.
//!
//! The semantic form is a signed coefficient and a base-ten scale. Leading
//! and trailing zeroes are removed, so mathematical equality, ordering and
//! hashing agree. The presentation class is intentionally kept out of those
//! operations: an integer token such as 1000 keeps the released integer
//! spelling, while 1e3 keeps the released fractional/exponent spelling
//! 1000.0. Arithmetic results use the fractional/exponent presentation class,
//! including 0.0 for an arithmetic zero.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// Maximum UTF-8 byte length accepted for one JSON number token.
pub const MAX_TOKEN_BYTES: usize = 4096;
/// Maximum number of significant decimal digits retained.
pub const MAX_SIGNIFICANT_DIGITS: usize = 1024;
/// Maximum absolute normalized base-ten scale.
pub const MAX_ABSOLUTE_SCALE: i32 = 1024;
/// Maximum exponent magnitude accepted before normalization.
pub const MAX_EXPONENT: i32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presentation {
    Integer,
    Fractional,
    Arithmetic,
}

/// A finite, bounded, exact base-ten number.
///
/// Values parsed from a token retain only the presentation distinction needed
/// to reproduce ordinary released output. This distinction never affects
/// PartialEq, Ord or Hash.
#[derive(Debug, Clone)]
pub struct ExactDecimal {
    /// -1 or 1 for non-zero values; zero is represented by an empty digit list.
    sign: i8,
    /// Significant coefficient digits, most significant first, with no leading
    /// or trailing zeroes for non-zero values.
    digits: Vec<u8>,
    /// digits * 10^(-scale).
    scale: i32,
    presentation: Presentation,
    negative_zero: bool,
}

/// Errors returned by parsing or checked arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecimalError {
    /// The input was empty or did not have JSON number-token syntax.
    InvalidToken,
    /// The token exceeded MAX_TOKEN_BYTES.
    TokenTooLong,
    /// The token's exponent exceeded MAX_EXPONENT.
    ExponentOutOfRange,
    /// The normalized value exceeded MAX_ABSOLUTE_SCALE.
    ScaleOutOfRange,
    /// The normalized coefficient exceeded MAX_SIGNIFICANT_DIGITS.
    TooManySignificantDigits,
    /// Checked arithmetic would exceed the bounded representation.
    ArithmeticOverflow,
    /// A tolerance must not be negative.
    NegativeTolerance,
}

impl fmt::Display for DecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidToken => "invalid JSON number token",
            Self::TokenTooLong => "JSON number token exceeds 4096 bytes",
            Self::ExponentOutOfRange => "JSON number exponent exceeds the supported bound",
            Self::ScaleOutOfRange => "normalized decimal scale exceeds the supported bound",
            Self::TooManySignificantDigits => "decimal coefficient exceeds 1024 significant digits",
            Self::ArithmeticOverflow => "exact decimal arithmetic exceeds the supported bound",
            Self::NegativeTolerance => "decimal tolerance must not be negative",
        };
        f.write_str(message)
    }
}

impl std::error::Error for DecimalError {}

impl FromStr for ExactDecimal {
    type Err = DecimalError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        Self::parse(token)
    }
}

impl TryFrom<&str> for ExactDecimal {
    type Error = DecimalError;

    fn try_from(token: &str) -> Result<Self, Self::Error> {
        Self::parse(token)
    }
}

impl fmt::Display for ExactDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_normalized_string())
    }
}

impl PartialEq for ExactDecimal {
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.scale == other.scale && self.digits == other.digits
    }
}

impl Eq for ExactDecimal {}

impl PartialOrd for ExactDecimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExactDecimal {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.sign.cmp(&other.sign) {
            Ordering::Equal => {}
            ordering => return ordering,
        }

        match self.sign {
            0 => Ordering::Equal,
            1 => compare_magnitude(self, other),
            -1 => compare_magnitude(other, self),
            _ => Ordering::Equal,
        }
    }
}

impl Hash for ExactDecimal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // These are the complete canonical semantic fields. Presentation and
        // negative-zero provenance are intentionally excluded.
        self.sign.hash(state);
        self.scale.hash(state);
        self.digits.hash(state);
    }
}

impl ExactDecimal {
    /// Parse one original JSON number token without converting it to binary
    /// floating point.
    pub fn parse(token: &str) -> Result<Self, DecimalError> {
        if token.is_empty() {
            return Err(DecimalError::InvalidToken);
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(DecimalError::TokenTooLong);
        }

        let bytes = token.as_bytes();
        let mut index = 0;
        let negative = if bytes[0] == b'-' {
            index += 1;
            true
        } else {
            false
        };
        if index == bytes.len() {
            return Err(DecimalError::InvalidToken);
        }

        let integer_start = index;
        match bytes[index] {
            b'0' => {
                index += 1;
                if index < bytes.len() && bytes[index].is_ascii_digit() {
                    return Err(DecimalError::InvalidToken);
                }
            }
            b'1'..=b'9' => {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
            }
            _ => return Err(DecimalError::InvalidToken),
        }
        let integer_end = index;

        let mut fraction_start = index;
        let mut fraction_end = index;
        let has_fraction = index < bytes.len() && bytes[index] == b'.';
        if has_fraction {
            index += 1;
            fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            fraction_end = index;
            if fraction_start == fraction_end {
                return Err(DecimalError::InvalidToken);
            }
        }

        let has_exponent = index < bytes.len() && matches!(bytes[index], b'e' | b'E');
        let exponent = if has_exponent {
            index += 1;
            let (value, next) = parse_exponent(bytes, index)?;
            index = next;
            value
        } else {
            0
        };
        if index != bytes.len() {
            return Err(DecimalError::InvalidToken);
        }

        let mut digits =
            Vec::with_capacity(integer_end - integer_start + fraction_end - fraction_start);
        digits.extend_from_slice(&bytes[integer_start..integer_end]);
        if has_fraction {
            digits.extend_from_slice(&bytes[fraction_start..fraction_end]);
        }

        let first_nonzero = digits
            .iter()
            .position(|digit| *digit != b'0')
            .unwrap_or(digits.len());
        let negative_zero = negative && first_nonzero == digits.len();
        let presentation = if has_fraction || has_exponent {
            Presentation::Fractional
        } else {
            Presentation::Integer
        };
        if first_nonzero == digits.len() {
            return Ok(Self {
                sign: 0,
                digits: Vec::new(),
                scale: 0,
                presentation,
                negative_zero,
            });
        }
        digits.drain(..first_nonzero);

        let raw_scale = fraction_end as i64 - fraction_start as i64 - i64::from(exponent);
        let scale = i32::try_from(raw_scale).map_err(|_| DecimalError::ScaleOutOfRange)?;
        Self::from_parts(negative, digits, scale, presentation, false)
    }

    /// True for the mathematical value zero, regardless of the source sign.
    pub const fn is_zero(&self) -> bool {
        self.sign == 0
    }

    /// True only for a non-zero negative value.
    pub const fn is_negative(&self) -> bool {
        self.sign < 0
    }

    /// Render the exact semantic value as a plain canonical decimal string.
    ///
    /// This is the stable identity/debug form: equal values have equal text,
    /// and no exponent or presentation marker is retained.
    pub fn to_key_string(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }
        let mut output = self.plain_magnitude();
        if self.is_negative() {
            output.insert(0, '-');
        }
        output
    }

    /// Render using the ordinary released JSON-number presentation rules.
    ///
    /// Integer source tokens remain integers when the released formatter would
    /// do so; fraction/exponent tokens and arithmetic results retain a decimal
    /// marker for ordinary integral values. Exact values outside the old
    /// binary-float range are not rounded: their exact coefficient is rendered
    /// in the same plain/scientific shape instead.
    pub fn to_normalized_string(&self) -> String {
        if self.is_zero() {
            if self.negative_zero {
                return "-0.0".to_owned();
            }
            return match self.presentation {
                Presentation::Integer => "0".to_owned(),
                Presentation::Fractional | Presentation::Arithmetic => "0.0".to_owned(),
            };
        }

        let adjusted = self.digits.len() as i32 - self.scale;
        let exponent = adjusted - 1;
        let integer_keeps_plain = self.integer_fits_released_range();
        let scientific = !integer_keeps_plain && (exponent <= -6 || exponent >= 16);
        let mut output = if scientific {
            self.scientific_magnitude(exponent)
        } else {
            self.plain_magnitude()
        };

        if !scientific
            && matches!(
                self.presentation,
                Presentation::Fractional | Presentation::Arithmetic
            )
            && !output.contains('.')
        {
            output.push_str(".0");
        }
        if self.is_negative() {
            output.insert(0, '-');
        }
        output
    }

    fn integer_fits_released_range(&self) -> bool {
        if self.presentation != Presentation::Integer || self.scale > 0 {
            return false;
        }
        let magnitude = self.plain_magnitude();
        let limit = if self.is_negative() {
            "9223372036854775808"
        } else {
            "18446744073709551615"
        };
        magnitude.len() < limit.len()
            || (magnitude.len() == limit.len() && magnitude.as_bytes() <= limit.as_bytes())
    }

    /// Add two exact values, refusing rather than truncating if the bounded
    /// representation cannot contain the result.
    pub fn checked_add(&self, other: &Self) -> Result<Self, DecimalError> {
        self.combine(other, false)
    }

    /// Subtract two exact values, refusing rather than truncating if the bounded
    /// representation cannot contain the result.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, DecimalError> {
        self.combine(other, true)
    }

    /// Return the exact absolute difference between two values.
    pub fn abs_diff(&self, other: &Self) -> Result<Self, DecimalError> {
        match self.cmp(other) {
            Ordering::Less => other.checked_sub(self),
            Ordering::Equal => Ok(Self::arithmetic_zero()),
            Ordering::Greater => self.checked_sub(other),
        }
    }

    /// Compare the exact absolute difference with a non-negative tolerance.
    pub fn within_tolerance(&self, other: &Self, tolerance: &Self) -> Result<bool, DecimalError> {
        if tolerance.is_negative() {
            return Err(DecimalError::NegativeTolerance);
        }
        Ok(self.abs_diff(other)? <= *tolerance)
    }

    fn arithmetic_zero() -> Self {
        Self {
            sign: 0,
            digits: Vec::new(),
            scale: 0,
            presentation: Presentation::Arithmetic,
            negative_zero: false,
        }
    }

    fn combine(&self, other: &Self, subtract: bool) -> Result<Self, DecimalError> {
        let other_sign = if subtract { -other.sign } else { other.sign };
        if self.sign == 0 {
            if other_sign == 0 {
                return Ok(Self::arithmetic_zero());
            }
            return Self::from_parts(
                other_sign < 0,
                other.digits.clone(),
                other.scale,
                Presentation::Arithmetic,
                false,
            );
        }
        if other_sign == 0 {
            return Self::from_parts(
                self.sign < 0,
                self.digits.clone(),
                self.scale,
                Presentation::Arithmetic,
                false,
            );
        }

        let target_scale = self.scale.max(other.scale);
        let left = aligned_digits(self, target_scale)?;
        let right = aligned_digits(other, target_scale)?;
        if self.sign == other_sign {
            let digits = add_digits(&left, &right);
            Self::from_parts(
                self.sign < 0,
                digits,
                target_scale,
                Presentation::Arithmetic,
                false,
            )
        } else {
            match compare_digits(&left, &right) {
                Ordering::Equal => Ok(Self::arithmetic_zero()),
                Ordering::Greater => {
                    let digits = subtract_digits(&left, &right);
                    Self::from_parts(
                        self.sign < 0,
                        digits,
                        target_scale,
                        Presentation::Arithmetic,
                        false,
                    )
                }
                Ordering::Less => {
                    let digits = subtract_digits(&right, &left);
                    Self::from_parts(
                        other_sign < 0,
                        digits,
                        target_scale,
                        Presentation::Arithmetic,
                        false,
                    )
                }
            }
        }
    }

    fn from_parts(
        negative: bool,
        mut digits: Vec<u8>,
        mut scale: i32,
        presentation: Presentation,
        negative_zero: bool,
    ) -> Result<Self, DecimalError> {
        while digits.first() == Some(&b'0') {
            digits.remove(0);
        }
        if digits.is_empty() {
            return Ok(Self {
                sign: 0,
                digits,
                scale: 0,
                presentation,
                negative_zero,
            });
        }
        while digits.last() == Some(&b'0') {
            digits.pop();
            scale = scale.checked_sub(1).ok_or(DecimalError::ScaleOutOfRange)?;
        }
        if digits.len() > MAX_SIGNIFICANT_DIGITS {
            return Err(DecimalError::TooManySignificantDigits);
        }
        if scale.unsigned_abs() > MAX_ABSOLUTE_SCALE as u32 {
            return Err(DecimalError::ScaleOutOfRange);
        }
        Ok(Self {
            sign: if negative { -1 } else { 1 },
            digits,
            scale,
            presentation,
            negative_zero: false,
        })
    }

    fn plain_magnitude(&self) -> String {
        debug_assert!(!self.is_zero());
        let digits = String::from_utf8(self.digits.clone()).expect("decimal digits are ASCII");
        if self.scale <= 0 {
            let zeroes = usize::try_from(-self.scale).expect("bounded scale");
            return format!("{digits}{}", "0".repeat(zeroes));
        }
        let scale = usize::try_from(self.scale).expect("bounded scale");
        if scale < digits.len() {
            let split = digits.len() - scale;
            format!("{}.{}", &digits[..split], &digits[split..])
        } else {
            format!("0.{}{}", "0".repeat(scale - digits.len()), digits)
        }
    }

    fn scientific_magnitude(&self, exponent: i32) -> String {
        debug_assert!(!self.is_zero());
        let digits = String::from_utf8(self.digits.clone()).expect("decimal digits are ASCII");
        let mut output = String::with_capacity(digits.len() + 12);
        output.push_str(&digits[..1]);
        if digits.len() > 1 {
            output.push('.');
            output.push_str(&digits[1..]);
        }
        output.push('e');
        if exponent >= 0 {
            output.push('+');
        }
        output.push_str(&exponent.to_string());
        output
    }
}

fn parse_exponent(bytes: &[u8], mut index: usize) -> Result<(i32, usize), DecimalError> {
    if index == bytes.len() {
        return Err(DecimalError::InvalidToken);
    }
    let negative = match bytes[index] {
        b'+' => {
            index += 1;
            false
        }
        b'-' => {
            index += 1;
            true
        }
        _ => false,
    };
    let start = index;
    let mut value = 0i32;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        let digit = i32::from(bytes[index] - b'0');
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .ok_or(DecimalError::ExponentOutOfRange)?;
        if value > MAX_EXPONENT {
            return Err(DecimalError::ExponentOutOfRange);
        }
        index += 1;
    }
    if index == start {
        return Err(DecimalError::InvalidToken);
    }
    Ok((if negative { -value } else { value }, index))
}

fn compare_magnitude(left: &ExactDecimal, right: &ExactDecimal) -> Ordering {
    let left_adjusted = left.digits.len() as i32 - left.scale;
    let right_adjusted = right.digits.len() as i32 - right.scale;
    match left_adjusted.cmp(&right_adjusted) {
        Ordering::Equal => {
            let length = left.digits.len().max(right.digits.len());
            for index in 0..length {
                let left_digit = left.digits.get(index).copied().unwrap_or(b'0');
                let right_digit = right.digits.get(index).copied().unwrap_or(b'0');
                match left_digit.cmp(&right_digit) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            Ordering::Equal
        }
        ordering => ordering,
    }
}

fn aligned_digits(value: &ExactDecimal, target_scale: i32) -> Result<Vec<u8>, DecimalError> {
    let shift = usize::try_from(target_scale - value.scale)
        .map_err(|_| DecimalError::ArithmeticOverflow)?;
    if shift > MAX_SIGNIFICANT_DIGITS + 1 {
        return Err(DecimalError::ArithmeticOverflow);
    }
    let mut digits = value.digits.clone();
    digits.resize(digits.len() + shift, b'0');
    Ok(digits)
}

fn compare_digits(left: &[u8], right: &[u8]) -> Ordering {
    match left.len().cmp(&right.len()) {
        Ordering::Equal => {}
        ordering => return ordering,
    }
    let left = left.iter().map(|digit| digit - b'0');
    let right = right.iter().map(|digit| digit - b'0');
    left.cmp(right)
}

fn add_digits(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut left_index = left.len();
    let mut right_index = right.len();
    let mut carry = 0u8;
    while left_index > 0 || right_index > 0 || carry != 0 {
        let left_digit = if left_index > 0 {
            left_index -= 1;
            left[left_index] - b'0'
        } else {
            0
        };
        let right_digit = if right_index > 0 {
            right_index -= 1;
            right[right_index] - b'0'
        } else {
            0
        };
        let sum = left_digit + right_digit + carry;
        output.push(b'0' + (sum % 10));
        carry = sum / 10;
    }
    output.reverse();
    output
}

fn subtract_digits(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(left.len());
    let mut left_index = left.len();
    let mut right_index = right.len();
    let mut borrow = 0u8;
    while left_index > 0 {
        left_index -= 1;
        let left_digit = left[left_index] - b'0';
        let right_digit = if right_index > 0 {
            right_index -= 1;
            right[right_index] - b'0'
        } else {
            0
        };
        let needed = right_digit + borrow;
        if left_digit < needed {
            output.push(b'0' + left_digit + 10 - needed);
            borrow = 1;
        } else {
            output.push(b'0' + left_digit - needed);
            borrow = 0;
        }
    }
    while output.last() == Some(&b'0') {
        output.pop();
    }
    output.reverse();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_json_number_grammar_errors() {
        for token in ["", "+1", ".1", "1.", "01", "1e", "1e+", "NaN", " 1"] {
            assert_eq!(
                ExactDecimal::parse(token),
                Err(DecimalError::InvalidToken),
                "{token:?}"
            );
        }
    }

    #[test]
    fn semantic_zero_ignores_all_source_spellings() {
        let values = ["-0", "-0.0", "0", "0.0", "0e5"]
            .into_iter()
            .map(ExactDecimal::parse)
            .collect::<Result<Vec<_>, _>>()
            .expect("zero spellings");
        for value in &values {
            assert_eq!(value, &values[0]);
            assert_eq!(value.cmp(&values[0]), Ordering::Equal);
        }
        let hashes = values
            .iter()
            .map(|value| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                value.hash(&mut hasher);
                hasher.finish()
            })
            .collect::<Vec<_>>();
        assert!(hashes.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(values[0].to_normalized_string(), "-0.0");
        assert_eq!(values[1].to_normalized_string(), "-0.0");
        assert_eq!(values[2].to_normalized_string(), "0");
        assert_eq!(values[3].to_normalized_string(), "0.0");
        assert_eq!(values[4].to_normalized_string(), "0.0");
    }

    #[test]
    fn addition_subtraction_and_difference_are_exact() {
        let left = ExactDecimal::parse("9007199254740992.1").expect("left");
        let right = ExactDecimal::parse("9007199254740992.2").expect("right");
        assert_eq!(
            left.checked_add(&right).expect("sum").to_key_string(),
            "18014398509481984.3"
        );
        assert_eq!(
            right
                .checked_sub(&left)
                .expect("difference")
                .to_key_string(),
            "0.1"
        );
        assert_eq!(
            left.abs_diff(&right)
                .expect("absolute difference")
                .to_key_string(),
            "0.1"
        );
        assert!(
            left.within_tolerance(&right, &ExactDecimal::parse("0.1").expect("tolerance"))
                .expect("tolerance comparison")
        );
        assert!(
            !left
                .within_tolerance(&right, &ExactDecimal::parse("0.09").expect("tolerance"))
                .expect("tolerance comparison")
        );
        assert_eq!(
            left.checked_sub(&left)
                .expect("zero")
                .to_normalized_string(),
            "0.0"
        );
    }

    #[test]
    fn limits_are_typed_and_bounded() {
        assert_eq!(
            ExactDecimal::parse("1e1000000000"),
            Err(DecimalError::ExponentOutOfRange)
        );
        assert_eq!(
            ExactDecimal::parse("1e-1000000000"),
            Err(DecimalError::ExponentOutOfRange)
        );
        assert_eq!(
            ExactDecimal::parse(&format!("1{}", "0".repeat(MAX_TOKEN_BYTES))),
            Err(DecimalError::TokenTooLong)
        );
        assert_eq!(
            ExactDecimal::parse(&format!("1{}", "2".repeat(MAX_SIGNIFICANT_DIGITS))),
            Err(DecimalError::TooManySignificantDigits)
        );
        assert_eq!(
            ExactDecimal::parse("1e1025"),
            Err(DecimalError::ExponentOutOfRange)
        );
    }
}
