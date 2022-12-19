# Simple RSA Implementation

As an exercise, I implemented RSA from scratch for Python >= 3.6.
I attempted to follow the system as it was [defined in this Wikipedia](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation>). Naturally, it would not be wise to use this in production -- opt for a tested and provenly safe implementation.

## Key generation

I repeatedly generate random odd numbers and perform a set of primality tests.
I start with the Fermat test, which ensures that for a prospective prime $p$, Fermat's Little Theorem holds for a default 40 random witness integers $a$, such that:
$$a^{p-1} \equiv 1 \text{(mod $p$)}$$
If this passes for all 40 witnesses, we continue to Miller-Rabin tests, as the Fermat tests will yield a false positive for any $a$ such that $gcd(a, p) = 1$, even if $p$ is not prime.

## Encryption

## Decryption
