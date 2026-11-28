"""Generate independent exact-decimal cases for the Rust test fixture.

This file only calculates expected values. It deliberately has no filesystem,
network, subprocess, dynamic-import, or code-evaluation capability.
"""

from decimal import Decimal
from fractions import Fraction
import json
import random
import sys


def plain_fraction(value):
    negative = value < 0
    value = abs(value)
    if value == 0:
        return "0"
    numerator = value.numerator
    denominator = value.denominator
    scale = 0
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise ValueError("oracle value is not a finite decimal")
    scale = max(twos, fives)
    numerator *= 2 ** (scale - twos)
    numerator *= 5 ** (scale - fives)
    digits = str(numerator)
    while scale and digits.endswith("0"):
        digits = digits[:-1]
        scale -= 1
    if scale == 0:
        result = digits
    elif scale < len(digits):
        split = len(digits) - scale
        result = digits[:split] + "." + digits[split:]
    else:
        result = "0." + ("0" * (scale - len(digits))) + digits
    return "-" + result if negative else result


def exact(token):
    return Fraction(Decimal(token))


def case(token, other):
    left = exact(token)
    right = exact(other)
    return {
        "left": token,
        "right": other,
        "left_key": plain_fraction(left),
        "right_key": plain_fraction(right),
        "sum_key": plain_fraction(left + right),
        "difference_key": plain_fraction(left - right),
        "absolute_difference_key": plain_fraction(abs(left - right)),
    }


def generated_tokens():
    rng = random.Random(0xDEC1A1)
    tokens = [
        "0",
        "-0",
        "0.0",
        "0e5",
        "1",
        "1.00",
        "1e0",
        "100",
        "1e2",
        "9007199254740992.1",
        "9007199254740992.2",
        "18446744073709551616",
        "1e-1024",
        "1e1024",
    ]
    for _ in range(128):
        digits = str(rng.randrange(1, 10**18))
        fraction_digits = str(rng.randrange(0, 10**6)).rjust(6, "0")
        exponent = rng.randrange(-18, 19)
        sign = "-" if rng.randrange(2) else ""
        tokens.append(f"{sign}{digits}.{fraction_digits}e{exponent:+d}")
    return tokens


def main():
    output = [
        {
            "source": "Python Decimal token conversion and Fraction arithmetic",
            "seed": "0xDEC1A1",
            "case_count": 0,
        }
    ]
    tokens = generated_tokens()
    for index in range(0, len(tokens) - 1, 2):
        output.append(case(tokens[index], tokens[index + 1]))
    output[0]["case_count"] = len(output) - 1
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
