# Simple RSA Implementation

As an exercise, I implemented RSA from scratch for Python >= 3.6.
I attempted to follow the system as it was [defined in this Wikipedia page](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation>). Naturally, it would not be wise to use this in production -- opt for a tested and provenly safe implementation.

## Key generation

### Generating Primes

For the key, we need to generate two large primes $p, q$.

To find large primes, we repeatedly generate random odd numbers and perform a series of primality tests.

#### Fermat Primality Test

I start with the Fermat test, which ensures that for a prospective prime $p$, Fermat's Little Theorem holds for a series of random witness integers $a \in [2, p-1]$, such that:
$$a^{p-1} \equiv 1 \text{(mod $p$)}$$
If this passes for all 40 witnesses, we continue to Miller-Rabin tests, as the Fermat tests will yield a false positive for any $a$ such that $gcd(a, p) = 1$, even if $p$ is not prime, as well as for the Carmichael numbers, though it is rare that we would encounter a Carmichael number when dealing with 1024 and 2048-bit integers.

#### Miller-Rabin Primality Test

The Miller-Rabin primality test relies on the fact that for prime modulus $p$ and witness integer $a$, the solutions to: $$a^2 \equiv 1 \text{(mod p)}$$ are exactly 1, -1, so we need only that $a^{(p-1)/2} \equiv \pm 1 \text{(mod p)}$. We continually square $\lfloor log_2(p-1) \rfloor$ times and ensure the statement continues to hold. Similar to the Fermat primality test, we repeat this test for 40 witnesses.

### Carmichael Function & Modular Multiplicative Inverse

The Carmichael function $\lambda(n)$ is the $m$ such that the degree mod $n$ of all numbers coprime to $n$ is $m$. We need this value to compute our multiplicative inverse exponent $d$ from our encryption exponent $e$ such that
$$ed \equiv 1 \text{ (mod $\lambda(n)$)}$$
Because $p, q$ prime, this is simply $\lambda(n) = \text{lcm}(p-1, q-1)$
Some implementations use Euler's totient $\phi(n) = (p-1)(q-1)$, but by using the Carmichael function, we can potentially yield a smaller value, which makes our computations more efficient. Either function is ok, because Euler's theorem holds for both.

In this implementation, I calculate the lcm using the following identity (and the gcd given by the [Euclidean algorithm](https://en.wikipedia.org/wiki/Euclidean_algorithm#Procedure))
$$\text{lcm(a, b)} = \frac{ab}{\text{gcd(a, b)}}$$

We choose our encryption exponent $e$ as a number coprime with $\lambda(n)$, as if they were not coprime, there would not be a unique inverse.

Finally, we need to calculate our inverse exponent $d$, so that we can recover our original message after it is raised to $d$ (mod n). This is the inverse of $e$ mod $\lambda(n)$. Why is that? We want $(m^e)^d \equiv m$ (mod $n$). Euler's theorem gives us:

$a^{\lambda(n)} \equiv 1$ (mod $n$)

$a^{\lambda(n)+1} \equiv a$ (mod $n$)

So we need the exponents to be equal:

$ed = \lambda(n) + 1$

But we can raise both sides of Euler's theorem to any exponent and it will still hold, so we just need to satisfy:

$ed \equiv 1 $(mod $\lambda(n)$)

So $d$ is the modular multiplicative inverse of $e$ (mod $\lambda(n)$)

### The Keys

The public key is comprised of the modulus $n=pq$ and the exponent $e$.

The private key is $d$, the multiplicative inverse of $e$. In my implementation, I also include the modulus $n$ as part of the private key so that we can decrypt without the public key.

Why is this secure?

If $e$ and $n$ are known, $d$ is the multiplicative ivnerse of $e$ mod $\lambda(n)$. But $\lambda(n)$ = $lcm(p, q)$. The only way to get $p, q$ is to factor $n$, which is impossibly difficult.

## Encryption & decryption

With the hard part out of the way, one can encrypt a plaintext message $m$ and decrypt a ciphertext message $c$ with modular exponentiation:
$$c \equiv m^e \text{ (mod $n$)}$$
$$m \equiv c^d \text{ (mod $n$)}$$
These are calculated efficiently using the binary [exponentiation by squaring method](https://en.wikipedia.org/wiki/Modular_exponentiation#Left-to-right_binary_method).
