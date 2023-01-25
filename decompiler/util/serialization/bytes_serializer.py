from decompiler.structures.pseudo.typing import Pointer, Type

LITTLE_ENDIAN = "little"
BIG_ENDIAN = "big"


def convert_bytes(bytestring: bytes, vartype: Type, endian: int = 0) -> int:
    """Serialize a bytestring into a number representation if possible"""
    if isinstance(vartype, Pointer):
        if vartype.type.size == 8 or vartype.type.size == 0:
            # If there are only printable characters, display it properly
            if bytestring.strip(b"\x00").isalnum():
                return bytestring.strip(b"\x00").decode("utf-8")
            # Otherwise display as a bytestring, it's probably not a proper string.
            converted = bytestring.hex("-").replace("-", "\\x")
            return f'"\\x{converted}"'
    # TODO: more variable types to be accounted for, when needed.
    return int.from_bytes(bytestring, LITTLE_ENDIAN if endian == 0 else BIG_ENDIAN)
