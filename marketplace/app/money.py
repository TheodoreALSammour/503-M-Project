"""Money helpers. All arithmetic is done on integer cents or Decimal - never float."""
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

MAX_PRICE_CENTS = 100_000_00  # $100,000.00 per unit


class MoneyError(ValueError):
    pass


def format_cents(cents):
    if cents is None:
        return None
    sign = "-" if cents < 0 else ""
    cents = abs(int(cents))
    return f"{sign}{cents // 100}.{cents % 100:02d}"


def parse_amount_to_cents(value, *, allow_zero=True, max_cents=MAX_PRICE_CENTS):
    """Parse a user supplied decimal amount ("19.99", 19.99 parsed as Decimal,
    or an integer number of dollars) into integer cents.

    Rejects floats, booleans, negatives, NaN/Infinity, more than 2 decimals."""
    if isinstance(value, bool) or isinstance(value, float):
        raise MoneyError("amount must be a decimal string or number with at most 2 decimals")
    if isinstance(value, int):
        dec = Decimal(value)
    elif isinstance(value, Decimal):
        dec = value
    elif isinstance(value, str):
        try:
            dec = Decimal(value.strip())
        except InvalidOperation:
            raise MoneyError("amount is not a valid decimal number")
    else:
        raise MoneyError("amount must be a decimal string or number")
    if not dec.is_finite():
        raise MoneyError("amount must be finite")
    if dec.as_tuple().exponent < -2:
        raise MoneyError("amount can have at most 2 decimal places")
    cents = int(dec * 100)
    if cents < 0:
        raise MoneyError("amount cannot be negative")
    if cents == 0 and not allow_zero:
        raise MoneyError("amount must be greater than zero")
    if cents > max_cents:
        raise MoneyError("amount is too large")
    return cents


def parse_percent_to_bp(value):
    """'12.5' -> 1250 basis points. Range (0, 100]."""
    if isinstance(value, bool) or isinstance(value, float):
        raise MoneyError("percent must be a decimal string or number")
    try:
        dec = Decimal(value if not isinstance(value, str) else value.strip())
    except (InvalidOperation, TypeError):
        raise MoneyError("percent is not a valid number")
    if not dec.is_finite() or dec.as_tuple().exponent < -2:
        raise MoneyError("percent can have at most 2 decimal places")
    bp = int(dec * 100)
    if bp < 1 or bp > 10000:
        raise MoneyError("percent must be greater than 0 and at most 100")
    return bp


def percentage_of(cents, percent_bp):
    """Percentage discount rounded HALF UP to the cent."""
    result = (Decimal(cents) * Decimal(percent_bp) / Decimal(10000)).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP)
    return int(result)
