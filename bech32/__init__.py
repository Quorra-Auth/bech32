# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
Reference implementation for Bech32, Bech32m, and segwit addresses.
Extended to support arbitrary data encoding for use-cases like LNURL,
Lightning Network invoices, and other protocols.
"""

from enum import Enum
from typing import Iterable, List, Optional, Tuple, Union


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Constant used by Bech32m (BIP-350), differs from classic Bech32's constant of 1
BECH32M_CONST = 0x2BC830A3


class Bech32Variant(Enum):
    """
    Enum to distinguish between Bech32 variants.

    - BECH32:   Original spec (BIP-173). Used for segwit v0, Lightning invoices, LNURL, etc.
    - BECH32M:  Newer spec (BIP-350). Used for segwit v1+ (e.g. Taproot/P2TR addresses).
    - UNKNOWN:  Checksum didn't match either variant (i.e. invalid).
    """
    BECH32 = 1
    BECH32M = BECH32M_CONST
    UNKNOWN = 0


def bech32_polymod(values: Iterable[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: Iterable[int]) -> Bech32Variant:
    """
    Verify a checksum given HRP and converted data characters.

    Returns the detected Bech32Variant, or Bech32Variant.UNKNOWN if invalid.
    """
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + list(data))
    if polymod == Bech32Variant.BECH32.value:
        return Bech32Variant.BECH32
    if polymod == Bech32Variant.BECH32M.value:
        return Bech32Variant.BECH32M
    return Bech32Variant.UNKNOWN


def bech32_create_checksum(hrp: str, data: Iterable[int], variant: Bech32Variant = Bech32Variant.BECH32) -> List[int]:
    """
    Compute the checksum values given HRP and data.

    Args:
        hrp:     The human-readable part.
        data:    The data to encode (5-bit values).
        variant: Which Bech32 variant to use for the checksum constant.
    """
    values = bech32_hrp_expand(hrp) + list(data)
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ variant.value
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: Iterable[int], variant: Bech32Variant = Bech32Variant.BECH32) -> str:
    """
    Compute a Bech32 (or Bech32m) string given HRP and data values.

    Args:
        hrp:     The human-readable part (e.g. "lnurl", "lnbc", "bc").
        data:    The data payload as 5-bit values.
        variant: BECH32 (default) or BECH32M.

    Returns:
        The encoded Bech32 string.
    """
    data = list(data)
    combined = data + bech32_create_checksum(hrp, data, variant)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(
    bech: str,
    max_length: int = 2000,  # Generous default to support LNURL and Lightning invoices
) -> Tuple[Optional[str], Optional[List[int]], Bech32Variant]:
    """
    Validate a Bech32 string and determine HRP, data, and variant.

    The original implementation capped length at 90 characters, which is correct
    for on-chain addresses (BIP-173) but too restrictive for:
      - Lightning Network invoices (BOLT-11): can be hundreds of characters
      - LNURL: base64url-encoded HTTPS URLs wrapped in Bech32, often 100-300+ chars

    Args:
        bech:       The Bech32-encoded string to decode.
        max_length: Maximum allowed string length (default 2000).

    Returns:
        A tuple of (hrp, data, variant). On failure, returns (None, None, Bech32Variant.UNKNOWN).
    """
    if len(bech) > max_length:
        return (None, None, Bech32Variant.UNKNOWN)
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None, Bech32Variant.UNKNOWN)
    if bech.lower() != bech and bech.upper() != bech:
        return (None, None, Bech32Variant.UNKNOWN)

    bech = bech.lower()
    pos = bech.rfind("1")

    # HRP must be at least 1 char, and data+checksum at least 6 chars
    if pos < 1 or pos + 7 > len(bech):
        return (None, None, Bech32Variant.UNKNOWN)
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return (None, None, Bech32Variant.UNKNOWN)

    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    variant = bech32_verify_checksum(hrp, data)

    if variant == Bech32Variant.UNKNOWN:
        return (None, None, Bech32Variant.UNKNOWN)

    return (hrp, data[:-6], variant)


def convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# ---------------------------------------------------------------------------
# Generic arbitrary-data encode / decode (LNURL, Lightning invoices, etc.)
# ---------------------------------------------------------------------------

def encode_bytes(hrp: str, payload: bytes, variant: Bech32Variant = Bech32Variant.BECH32) -> Optional[str]:
    """
    Encode arbitrary bytes into a Bech32 string.

    This is the right function to use for LNURL and Lightning invoices,
    where the payload is not a segwit witness program but raw bytes
    (e.g. a URL or a BOLT-11 invoice structure).

    Args:
        hrp:     Human-readable part (e.g. "lnurl", "lnbc").
        payload: Raw bytes to encode.
        variant: Bech32 variant (default: BECH32).

    Returns:
        Bech32-encoded string, or None if conversion fails.

    Example:
        >>> url = b"https://service.example/lnurl-pay"
        >>> encoded = encode_bytes("lnurl", url)
    """
    five_bit_data = convertbits(payload, 8, 5, pad=True)
    if five_bit_data is None:
        return None
    return bech32_encode(hrp, five_bit_data, variant)


def decode_bytes(
    hrp: str,
    bech: str,
    variant: Bech32Variant = Bech32Variant.BECH32,
) -> Optional[bytes]:
    """
    Decode a Bech32 string back to raw bytes, verifying the HRP and variant.

    Args:
        hrp:     Expected human-readable part (e.g. "lnurl"). Pass "" to skip HRP check.
        bech:    The Bech32-encoded string.
        variant: Expected Bech32 variant (default: BECH32).

    Returns:
        Decoded bytes, or None if decoding/validation fails.

    Example:
        >>> decoded = decode_bytes("lnurl", encoded)
        >>> print(decoded)
        b'https://service.example/lnurl-pay'
    """
    got_hrp, data, got_variant = bech32_decode(bech)

    if got_hrp is None or data is None:
        return None
    if hrp and got_hrp != hrp.lower():
        return None
    if got_variant != variant:
        return None

    decoded = convertbits(data, 5, 8, pad=False)
    if decoded is None:
        return None

    return bytes(decoded)


# ---------------------------------------------------------------------------
# Segwit-specific encode / decode (unchanged semantics, updated signatures)
# ---------------------------------------------------------------------------

def decode(hrp: str, addr: str) -> Union[Tuple[None, None], Tuple[int, List[int]]]:
    """
    Decode a segwit address.

    Validates that:
      - The HRP matches.
      - The witness version is in range [0, 16].
      - Witness version 0 uses Bech32; versions 1+ use Bech32m.
      - The witness program length is valid (2-40 bytes, 20 or 32 for v0).
    """
    hrpgot, data, variant = bech32_decode(addr, max_length=90)

    if hrpgot != hrp or data is None or len(data) < 1:
        return (None, None)

    witver = data[0]
    if witver > 16:
        return (None, None)

    # BIP-350: v0 uses Bech32, v1+ uses Bech32m
    expected_variant = Bech32Variant.BECH32 if witver == 0 else Bech32Variant.BECH32M
    if variant != expected_variant:
        return (None, None)

    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if witver == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)

    return (witver, decoded)


def encode(hrp: str, witver: int, witprog: Iterable[int]) -> Optional[str]:
    """
    Encode a segwit address.

    Automatically selects Bech32 for witness version 0,
    and Bech32m for witness versions 1-16 (BIP-350).
    """
    variant = Bech32Variant.BECH32 if witver == 0 else Bech32Variant.BECH32M
    five_bit_witprog = convertbits(list(witprog), 8, 5)
    if five_bit_witprog is None:
        return None
    ret = bech32_encode(hrp, [witver] + five_bit_witprog, variant)
    if decode(hrp, ret) == (None, None):
        return None
    return ret
