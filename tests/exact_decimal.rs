use std::collections::HashSet;

use cmdrvl_core::exact_decimal::{
    DecimalError, ExactDecimal, MAX_ABSOLUTE_SCALE, MAX_SIGNIFICANT_DIGITS,
};
use serde_json::Value;

fn decimal(token: &str) -> ExactDecimal {
    ExactDecimal::parse(token).unwrap()
}

fn oracle_text<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("INVALID_ORACLE_FIELD")
}

fn bounded_plain(value: &str) -> bool {
    let value = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    let mut digits = format!("{integer}{fraction}")
        .trim_start_matches('0')
        .to_owned();
    if digits.is_empty() {
        return true;
    }
    let mut scale = fraction.len() as i32;
    while scale > 0 && digits.ends_with('0') {
        digits.pop();
        scale -= 1;
    }
    digits.len() <= MAX_SIGNIFICANT_DIGITS && scale.unsigned_abs() <= MAX_ABSOLUTE_SCALE as u32
}

#[test]
fn released_presentation_table_is_explicit() {
    // hashbytes v0.6.0 was measured from SHA256SUMS-verified release assets.
    // The exact type agrees for ordinary values and deliberately differs where
    // the released f64 path rounded a value outside its exact range.
    let cases = [
        ("1.50", "1.5", "1.5"),
        ("1e3", "1000.0", "1000.0"),
        ("-0", "-0.0", "-0.0"),
        ("0", "0", "0"),
        ("0e5", "0.0", "0.0"),
        ("1e308", "1e+308", "1e+308"),
        ("1e-308", "1e-308", "1e-308"),
        ("9007199254740992", "9007199254740992", "9007199254740992"),
        ("9007199254740993", "9007199254740993", "9007199254740993"),
        (
            "18446744073709551615",
            "18446744073709551615",
            "18446744073709551615",
        ),
        (
            "18446744073709551616",
            "1.8446744073709552e+19",
            "1.8446744073709551616e+19",
        ),
    ];
    for (token, released, exact) in cases {
        let value = decimal(token);
        assert_eq!(value.to_normalized_string(), exact, "{token}");
        if released == exact {
            assert_eq!(
                released, exact,
                "ordinary release spelling changed for {token}"
            );
        } else {
            assert_ne!(
                released, exact,
                "the exact path must not repeat the released f64 rounding for {token}"
            );
        }
    }
}

#[test]
fn mathematical_identity_is_separate_from_presentation() {
    let equal_spellings = ["1", "1.0", "1.00", "1e0"]
        .into_iter()
        .map(decimal)
        .collect::<Vec<_>>();
    assert!(equal_spellings.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(decimal("100"), decimal("1e2"));
    assert_ne!(decimal("1"), decimal("1e2"));
    assert_ne!(decimal("9007199254740992.1"), decimal("9007199254740992.2"));
    assert_eq!(decimal("1e3").to_key_string(), "1000");
    assert_eq!(decimal("1e3").to_normalized_string(), "1000.0");

    let unique = equal_spellings.into_iter().collect::<HashSet<_>>();
    assert_eq!(unique.len(), 1);
    assert_eq!(
        ExactDecimal::parse("\"1\""),
        Err(DecimalError::InvalidToken)
    );
}

#[test]
fn exact_arithmetic_covers_signs_extremes_and_subnormals() {
    assert_eq!(
        decimal("99999999999999999999999999999999999999999999999999.9")
            .checked_add(&decimal("0.1"))
            .expect("same-sign near maximum"),
        decimal("100000000000000000000000000000000000000000000000000")
    );
    assert_eq!(
        decimal("99999999999999999999999999999999999999999999999999.9")
            .checked_add(&decimal(
                "-99999999999999999999999999999999999999999999999999.8"
            ))
            .expect("opposite-sign near maximum"),
        decimal("0.1")
    );
    assert_eq!(
        decimal("1e-1024")
            .checked_add(&decimal("1e-1024"))
            .expect("subnormal-scale addition"),
        decimal("2e-1024")
    );
    assert_eq!(
        decimal("123.456")
            .abs_diff(&decimal("123.456"))
            .expect("equal bounds"),
        decimal("0")
    );
    assert_eq!(
        decimal("10")
            .checked_sub(&decimal("0.1"))
            .expect("ordinary subtraction")
            .to_key_string(),
        "9.9"
    );
    assert_eq!(
        decimal("1")
            .checked_sub(&decimal("1"))
            .expect("arithmetic zero")
            .to_normalized_string(),
        "0.0"
    );
    assert!(
        decimal("1.00")
            .within_tolerance(&decimal("1.000"), &decimal("0"))
            .expect("equal tolerance")
    );
    assert_eq!(
        decimal("1.00").within_tolerance(&decimal("1.1"), &decimal("-0.1")),
        Err(DecimalError::NegativeTolerance)
    );
}

#[test]
fn independent_decimal_fraction_oracle_matches_bounded_operations() {
    let fixture: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/exact_decimal_oracle.json"))
            .expect("Python oracle fixture is valid JSON");
    assert_eq!(fixture[0]["case_count"], 71);
    assert_eq!(
        fixture[0]["source"],
        "Python Decimal token conversion and Fraction arithmetic"
    );

    for case in fixture.iter().skip(1) {
        let left = decimal(oracle_text(case, "left"));
        let right = decimal(oracle_text(case, "right"));
        assert_eq!(left.to_key_string(), oracle_text(case, "left_key"));
        assert_eq!(right.to_key_string(), oracle_text(case, "right_key"));

        let expected_sum = oracle_text(case, "sum_key");
        match left.checked_add(&right) {
            Ok(actual) if bounded_plain(expected_sum) => {
                assert_eq!(actual.to_key_string(), expected_sum, "{case}");
            }
            Err(_) if !bounded_plain(expected_sum) => {}
            Ok(actual) => {
                assert!(
                    bounded_plain(expected_sum),
                    "unexpected bounded sum for {case}: {actual:?}"
                );
                assert_eq!(actual.to_key_string(), expected_sum, "{case}");
            }
            Err(error) => {
                assert!(
                    !bounded_plain(expected_sum),
                    "unexpected sum refusal for {case}: {error}"
                );
            }
        }

        let expected_difference = oracle_text(case, "difference_key");
        match left.checked_sub(&right) {
            Ok(actual) if bounded_plain(expected_difference) => {
                assert_eq!(actual.to_key_string(), expected_difference, "{case}");
            }
            Err(_) if !bounded_plain(expected_difference) => {}
            Ok(actual) => {
                assert!(
                    bounded_plain(expected_difference),
                    "unexpected bounded difference for {case}: {actual:?}"
                );
                assert_eq!(actual.to_key_string(), expected_difference, "{case}");
            }
            Err(error) => {
                assert!(
                    !bounded_plain(expected_difference),
                    "unexpected difference refusal for {case}: {error}"
                );
            }
        }

        let expected_absolute = oracle_text(case, "absolute_difference_key");
        match left.abs_diff(&right) {
            Ok(actual) if bounded_plain(expected_absolute) => {
                assert_eq!(actual.to_key_string(), expected_absolute, "{case}");
            }
            Err(_) if !bounded_plain(expected_absolute) => {}
            Ok(actual) => {
                assert!(
                    bounded_plain(expected_absolute),
                    "unexpected bounded absolute difference for {case}: {actual:?}"
                );
                assert_eq!(actual.to_key_string(), expected_absolute, "{case}");
            }
            Err(error) => {
                assert!(
                    !bounded_plain(expected_absolute),
                    "unexpected absolute-difference refusal for {case}: {error}"
                );
            }
        }
    }
}
