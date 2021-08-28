# PktSeed
This is the seed algorithm used in PktWallet.

## Why another seed algotithm?!
1. **Versions**: BIP-32 has no version so it cannot be updated, ever
2. **Encryption**: Seeds can optionally be encrypted using a passphrase stretched with Argon2 for
significant additional safety.
3. **Checksums**: A single wrong word is quickly detected without a confusing decryption failure.
3. **Birthdays**: Seeds contain a datestamp with the day when the seed (wallet) was created,
so wallet implementations can re-sync from seed without scanning the entire history of the blockchain.
4. **Brief**: Only 15 words long, as brief as possible with 136 bit security.


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
    let seed = seed_enc.decrypt(b"password").unwrap();
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