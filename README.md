# Skhoron-Passgen

A password generator with protection against modulo bias (rejection sampling) and
hashing/verification using Argon2id. Part of the "Skhoron" (https://github.com/Skhoron) ecosystem.

What's Custom and What's Provided by Libraries

Component| Who Wrote It| Why
Randomness source ("OsRng")| Library ("rand")| You must not invent your own RNG — this is the one area in cryptography where doing so is absolutely unacceptable
Rejection sampling (protection against modulo bias)| Custom code| This is arithmetic, not a cryptographic primitive
Password hashing function (Argon2id)| Library ("argon2")| Standardized in RFC 9106, with years of public analysis
Salt generation| Library ("password-hash", internally uses OsRng)| A salt is also random bytes, following the same principle as an RNG
CLI, storage, charset handling, entropy calculation| Custom code| Ordinary logic, not cryptography

No cryptographic primitive (RNG, hash function) is implemented
from scratch — only the logic around them.

Features

# Simply generate a password
skhoron-passgen generate --length 24

# Several options to choose from
skhoron-passgen generate --length 20 --count 5

# Generate, display once, and save the hash under a label
skhoron-passgen new my-email-account --length 24

# Later, verify whether the correct password was entered (for example, to check that you correctly
# wrote down/remembered the generated password)
skhoron-passgen verify my-email-account

# List saved labels
skhoron-passgen list

Important Notes About Storage

The storage file (by default "skhoron-passgen-store.txt") contains
only Argon2id hashes, not the passwords themselves — it is safe to store this as plain
text, like "/etc/shadow". It is not possible to recover a password from its hash,
only to verify a match (you must save the password yourself at
the time of generation — it is displayed only once).

Labels in the file are stored as plain text — if you need
the labels themselves to remain confidential, consider encrypting the entire file
with a separate layer (for example, using XChaCha20-Poly1305); this is intentionally not implemented
here, to avoid mixing a password generator with a full-fledged
password manager.

Build and Tests

cargo build --release
cargo test
cargo clippy -- -D warnings

«Build and run the tests locally before use.»

License

Apache License 2.0.