import secrets
import math
import sys
from pem import write_private_key, write_public_key


class SimpleRSA:
    def __init__(self):
        self.DEFAULT_WITNESS_COUNT = 40
        self.secure_rng = secrets.SystemRandom()

    def _modular_pow(self, base, exponent, modulus):
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

    def _fermat_prime(self, number, witnesses):
        """
        Ensure that fermat's little theorem holds for a set number of witnesses
        For a high number of witnesses, there is a high probability that the number is prime
        Will pass for carmichael numbers, so subsequently need to run Miller-Rabin
        """
        if number == 2 or number == 1:
            return True
        for _ in range(witnesses):
            witness = self.secure_rng.randrange(
                2, number-1)  # number-1 exclusive
            if self._modular_pow(witness, number-1, number) != 1:
                return False
        return True

    def _miller_rabin_prime(self, number, witnesses):
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
            a = self.secure_rng.randrange(2, number-1)  # number-1 exclusive
            x = self._modular_pow(a, d, number)
            for _ in range(s):
                y = self._modular_pow(x, 2, number)
                if y == 1 and x != 1 and x != number-1:
                    return False
                x = y
            if y != 1:
                return False
        return True

    def _find_prime(self, size):
        """
        Repeatedly generates random 'size'-bit integers until one passes fermat and miller-rabin primality tests
        """
        while True:
            candidate = secrets.randbits(size)
            # ensure odd number, as all primes > 2 are odd
            if candidate & 1 == 0:
                candidate += 1
            if self._fermat_prime(candidate, self.DEFAULT_WITNESS_COUNT):
                if self._miller_rabin_prime(candidate, self.DEFAULT_WITNESS_COUNT):
                    return candidate

    def _gcd_euclidean(self, a, b):
        """
        Calculates GCD of two numbers using Euclidean algorithm
        https://en.wikipedia.org/wiki/Euclidean_algorithm#Procedure
        """
        while b > 0:
            r = a % b
            a = b
            b = r
        return a

    def _lcm(self, a, b):
        """
        Uses GCD from Euclidean algorithm to find LCM
        lcm(a, b) = |ab| / gcd(a, b)
        """
        return (a*b) // self._gcd_euclidean(a, b)

    def _mod_mult_inverse(self, a, n):
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

    def generate_keypair(self, size):
        """
        Generates a 'size'-bit RSA keypair
        Returns tuple (public, private)
        where public = tuple(n, e)
        and private = tuple(n, d)
        """
        prime_size = size // 2
        p = self._find_prime(prime_size)
        q = self._find_prime(prime_size)
        n = p*q
        # carmichael function (p, q) = lcm(p-1, q-1)
        lam = self._lcm(p-1, q-1)
        # choose an e that is coprime with lamda
        e = (2 ^ 16) + 1
        while self._gcd_euclidean(e, lam) != 1:
            e = self.secure_rng.randrange(3, lam)
        public_key = (n, e)
        d = self._mod_mult_inverse(e, lam)
        private_key = (n, d)
        self.public_key, self.private_key = public_key, private_key
        return public_key, private_key

    def encrypt(self, plaintext):
        """
        Encrypts text given public_key = tuple(n, e)
        """
        if not self.public_key:
            raise Exception(
                "No public key is set. A public key is required to encrypt")
        n, e = self.public_key
        if type(plaintext) == str:
            plaintext = int.from_bytes(
                plaintext.encode(), byteorder=sys.byteorder)
        return self._modular_pow(plaintext, e, n)

    def decrypt(self, encrypted_text, type=str):
        """
        Decrypts text given private_key = n, d
        """
        if not self.private_key:
            raise Exception(
                "No private key is set. A private key is required to decrypt")
        n, d = self.private_key
        plainint = self._modular_pow(encrypted_text, d, n)
        if type == str:
            length = math.ceil(plainint.bit_length() / 8)
            data = plainint.to_bytes(length, sys.byteorder)
            return data.decode()
        return plainint

    def save_public_key(self, path):
        """
        Saves a public key to PKCS#1 PEM format (rfc 8017)
        https://datatracker.ietf.org/doc/html/rfc8017
        """
        if not self.public_key:
            raise Exception("No public key is set")
        write_public_key(self.public_key, path)

    def save_private_key(self, path):
        """
        Saves a private key to PKCS#1 PEM format (rfc 8017)
        https://datatracker.ietf.org/doc/html/rfc8017
        """
        if not self.private_key:
            raise Exception("No private key is set")
        write_private_key(self.private_key, path)

    def load_public_key(self, path):
        """
        Loads a PKCS#1 PEM formatted public key (rfc 8017)
        https://datatracker.ietf.org/doc/html/rfc8017#section-3.2
        """
        pass

    def load_private_key(self, path):
        """
        Loads a PKCS#1 PEM formatted private key (rfc 8017)
        https://datatracker.ietf.org/doc/html/rfc8017#section-3.2
        """
        pass
