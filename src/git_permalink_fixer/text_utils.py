from typing import Tuple


def parse_tolerance_input(tolerance_str: str) -> Tuple[bool, int]:
    """
    Parses the line shift tolerance string and validates it.
    Returns: (is_percentage, value)
    Raises ValueError if the format or value is invalid.
    """
    if tolerance_str.endswith("%"):
        try:
            val = int(tolerance_str[:-1])
            if not 0 <= val <= 100:
                raise ValueError("Percentage tolerance must be between 0% and 100%.")
            return True, val
        except ValueError as e:
            raise ValueError(f"Invalid percentage tolerance format '{tolerance_str}': {e}") from e
    else:
        try:
            val = int(tolerance_str)
            if val < 0:
                raise ValueError("Absolute line shift tolerance cannot be negative.")
            return False, val
        except ValueError as e:
            raise ValueError(f"Invalid absolute tolerance format '{tolerance_str}': {e}") from e
