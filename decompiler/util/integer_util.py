def normalize_int(v: int, size: int, signed: bool) -> int:
    """
    Normalizes an integer value to a specific size and signedness.

    This function takes an integer value 'v' and normalizes it to fit within
    the specified 'size' in bits by discarding overflowing bits. If 'signed' is
    true, the value is treated as a signed integer, i.e. interpreted as a two's complement.
    Therefore the return value will be negative iff 'signed' is true and the most-significant bit is set.

    :param v: The value to be normalized.
    :param size: The desired bit size for the normalized integer.
    :param signed: True if the integer should be treated as signed.
    :return: The normalized integer value.
    """
    value = v & ((1 << size) - 1)
    if signed and value & (1 << (size - 1)):
        return value - (1 << size)
    else:
        return value
