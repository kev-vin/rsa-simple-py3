import secrets

DEFAULT_WITNESS_COUNT = 40
secure_rng = secrets.SystemRandom()


def modular_pow(base, exponent, modulus):
    """
    Uses exponentiation by squaring to efficiently exponentiate:
        base^exponent (mod modulus)
    https://en.wikipedia.org/wiki/Modular_exponentiation#Left-to-right_binary_method
    """
    if modulus == 1:
        return 0
    base = base % modulus
    result = 1
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def fermat_prime(number, witnesses=DEFAULT_WITNESS_COUNT):
    """
    Ensure that fermat's little theorem holds for a set number of witnesses
    For a high number of witnesses, there is a high probability that the number is prime
    Will pass for carmichael numbers, so subsequently need to run Miller-Rabin
    """
    if number == 2 or number == 1:
        return True
    for _ in range(witnesses):
        witness = secure_rng.randrange(2, number-1)  # number-1 exclusive
        if modular_pow(witness, number-1, number) != 1:
            return False
    return True


def miller_rabin_prime(number, witnesses=DEFAULT_WITNESS_COUNT):
    """
    Uses miller-rabin primality test
    Checks both that FLT holds and that the only square roots mod n of 1 are -1 and 1
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    """
    if number != 2 and number & 1 == 0:
        # number > 2 and even, cannot be prime
        return False
    s = 0
    d = number - 1
    while d & 1 == 0:
        # factor out powers of 2 until d odd s.t n-1 = 2^s d
        s += 1
        d = d >> 1
    for _ in range(witnesses):
        a = secure_rng.randrange(2, number-1)  # number-1 exclusive
        x = modular_pow(a, d, number)
        for _ in range(s):
            y = modular_pow(x, 2, number)
            if y == 1 and x != 1 and x != number-1:
                return False
            x = y
        if y != 1:
            return False
    return True


def find_prime(size):
    """
    Repeatedly generates random 'size'-bit integers until one passes fermat and miller-rabin primality tests
    """
    while True:
        candidate = secrets.randbits(size)
        # ensure odd number, as all primes > 2 are odd
        if candidate & 1 == 0:
            candidate += 1
        if fermat_prime(candidate):
            if miller_rabin_prime(candidate):
                return candidate


def gcd_euclidean(a, b):
    """
    Calculates GCD of two numbers using Euclidean algorithm
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Procedure
    """
    while b > 0:
        r = a % b
        a = b
        b = r
    return a


def lcm(a, b):
    """
    Uses GCD from Euclidean algorithm to find LCM
    lcm(a, b) = |ab| / gcd(a, b)
    """
    return (a*b) // gcd_euclidean(a, b)


def mod_mult_inverse(a, n):
    """
    Finds modular multiplicative inverse of a mod n
    https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
    """
    # express gcd(a, n) as a linear combination of a, n
    old_r, r = a, n
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - (quotient * r)
        old_s, s = s, old_s - (quotient * s)

    # apply bezout's identity
    return (old_s % n + n) % n


def generate_keypair(size):
    """
    Generates a 'size'-bit RSA keypair
    Returns tuple (public, private)
    where public = tuple(n, e)
    and private = tuple(n, d)
    """
    prime_size = size // 2
    p = find_prime(prime_size)
    q = find_prime(prime_size)
    n = p*q
    # carmichael function (p, q) = lcm(p-1, q-1) bc euler's totient(p) = p-1
    lam = lcm(p-1, q-1)
    # choose an e that is coprime with lamda
    e = (2 ^ 16) + 1
    while gcd_euclidean(e, lam) != 1:
        e = secure_rng.randrange(3, lam)
    public_key = (n, e)
    d = mod_mult_inverse(e, lam)
    private_key = (n, d)
    return public_key, private_key


def encrypt(public_key, plaintext):
    """
    Encrypts text given public_key = tuple(n, e)
    """
    n, e = public_key
    return modular_pow(plaintext, e, n)


def decrypt(private_key, encrypted_text):
    """
    Decrypts text given private_key = d
    """
    n, d = private_key
    return modular_pow(encrypted_text, d, n)
