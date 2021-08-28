# PktSeed
This is the seed algorithm used in PktWallet.

## Why another seed algotithm?!
1. **Versions**: BIP-39 has no version so it cannot be updated, ever
2. **Encryption**: Seeds can optionally be encrypted using a passphrase stretched with Argon2 for
significant additional safety. BIP-39 also allows a passphrase, but the passphrase is *hashed* with the
seed rather than being used to encrypt it, so a BIP-39 passphrase can never be changed but a PKT passphrase
can be changed any time and will simply result in a new word-based representation of the seed.
3. **Checksums**: A single wrong word is quickly detected without a confusing decryption failure.
The birthday also serves as an additional few bits of checksum because seeds which declare a birthday
from before this seed algorithm was first released, or one in the future, are rejected.
3. **Birthdays**: Seeds contain a datestamp with the day when the seed (wallet) was created,
so wallet implementations can re-sync from seed without scanning the entire history of the blockchain.
4. **Convention Over Configuration**: All PKT seed phrases are exactly 15 words long and provide 136 bits
of security, a security level which is recognized as adaquate in the cryptography community.
BIP-39 defines 12, 15, 18, 21 and 24 word seeds, punting the question of appropriate security level
to the end users, many of whom would select 200 word seeds if they were so offered.

## How do I?

### Make an encrypted seed and output the words

```rust
use rand::Rng;
use pktseed::{Seed, SeedEnc};
fn main() {
    let mut rng = rand::thread_rng();
    let seed = Seed::new(rng.gen::<[u8; 17]>());
    let seed_enc = seed.encrypt(Some(b"password"));
    println!("Encrypted seed words: {}", seed_enc.words("english"));
}
```

### Make an unencrypted seed

```rust
use rand::Rng;
use pktseed::{Seed, SeedEnc};
fn main() {
    let mut rng = rand::thread_rng();
    let seed = Seed::new(rng.gen::<[u8; 17]>());
    let seed_enc = seed.encrypt(None);
    println!("Unencrypted seed words: {}", seed_enc.words("english"));
}
```

### Check if a seed is encrypted

```rust
use pktseed::SeedEnc;
fn main() {
    let seed_enc = SeedEnc::from_words(
        "mom blanket bulk draw clip wolf bread erupt merry skin cable infant word exchange animal",
    ).unwrap();
    println!("Is seed encrypted? {}", seed_enc.is_encrypted());
}
```

### Decrypt seed

```rust
use pktseed::SeedEnc;
fn main() {
    let seed_enc = SeedEnc::from_words(
        "mom blanket bulk draw clip wolf bread erupt merry skin cable infant word exchange animal",
    ).unwrap();
    let seed = seed_enc.decrypt(b"password", false).unwrap();
    println!("Decrypted seed bytes: {}", hex::encode(&seed.bytes[..]));
}
```

## C API
Re-generating header:  `cargo build --release --features generate-capi`

## Languages
To compile with additional language support you can use:

```
cargo build --release --features lang-spanish lang-french lang-czech
```

## License

[Apache2](https://spdx.org/licenses/Apache-2.0.html) OR
[MIT](https://spdx.org/licenses/MIT.html), at your option.