CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):

    generator = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]

    chk = 1

    for v in values:

        b = chk >> 25

        chk = ((chk & 0x1ffffff) << 5) ^ v

        for i in range(5):

            if ((b >> i) & 1):
                chk ^= generator[i]

    return chk


def bech32_hrp_expand(hrp):

    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):

    return bech32_polymod(
        bech32_hrp_expand(hrp) + data
    ) == 1


def bech32_decode(bech):

    bech = bech.lower()

    pos = bech.rfind("1")

    if pos < 1:
        return (None, None)

    hrp = bech[:pos]

    data = []

    for c in bech[pos + 1:]:

        if c not in CHARSET:
            return (None, None)

        data.append(
            CHARSET.find(c)
        )

    if not bech32_verify_checksum(hrp, data):
        return (None, None)

    return hrp, data[:-6]


def convertbits(data, frombits, tobits, pad=True):

    acc = 0
    bits = 0

    ret = []

    maxv = (1 << tobits) - 1

    for value in data:

        acc = (acc << frombits) | value
        bits += frombits

        while bits >= tobits:

            bits -= tobits

            ret.append(
                (acc >> bits) & maxv
            )

    if pad:

        if bits:
            ret.append(
                (acc << (tobits - bits)) & maxv
            )

    elif bits >= frombits or (
        (acc << (tobits - bits)) & maxv
    ):
        return None

    return ret


def decode_segwit_address(addr):

    hrp, data = bech32_decode(addr)

    if hrp is None:
        raise Exception("Invalid bech32")

    decoded = convertbits(
        data[1:],
        5,
        8,
        False
    )

    return bytes(decoded)
