import base64

START_MARKER_TEMPLATE = "-----BEGIN %s KEY-----"
END_MARKER_TEMPLATE = "-----END %s KEY-----"
DER_INTEGER_TYPE = 0x02


def to_der_sequence(*args):
    """
    Creates a der sequence from provided data
    """
    pass


def write_private_key(key_tuple, path):
    """
    Takes a tuple of (modulus, private exponent) and writes to file in PKCS#1 PEM format (without chinese remainder theorem fields)
    rfc8017
    """
    start_marker = START_MARKER_TEMPLATE.format("PRIVATE")
    end_marker = END_MARKER_TEMPLATE.format("PRIVATE")
    der = to_der_sequence(key_tuple)
    data = base64.b64encode(der)
    # TODO: Insert line breaks every 64 chars
    pass


def write_public_key(key_tuple, path):
    """
    Takes a tuple of (modulus, encryption/public exponent) and writes to file in PKCS#1 PEM format
    rfc8017
    """
    start_marker = START_MARKER_TEMPLATE.format("PUBLIC")
    end_marker = END_MARKER_TEMPLATE.format("PUBLIC")
    der = to_der_sequence(key_tuple)
    data = base64.b64encode(der)
    # TODO: Insert line breaks every 64 chars
    pass
