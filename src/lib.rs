// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::One;
use zeroize::Zeroizing;

mod words;
mod capi;

/// Representation of a wallet seed which can be output as words.
///
/// Seed layout:
///     0               1               2               3
///     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |  U  |  Ver  |E|   Checksum    |           Birthday            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                                                               |
///    +                                                               +
///  8 |                                                               |
///    +                               Seed                            +
/// 12 |                                                               |
///    +                                                               +
/// 16 |                                                               |
///    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 |               |
///    +-+-+-+-+-+-+-+-+
/// 
/// U: unused: Cannot be used because there are only 165 bits in 15 11 bit words. When decoding
///            the bignum is initialized to 1, which causes unused to be set to 1 so EXPECT_UNUSED
///            is 1, but after decoding then unused is cleared to zero.
/// Ver: 0
/// E: 1 if there is a passphrase encrypting the seed, 0 otherwise
/// Checksum: first byte of blake2b of structure with Checksum and Unused cleared
/// Birthday (encrypted): when the wallet was created, unix time divided by 60*60*24, big endian
/// Seed (encrypted): 17 byte seed content
#[derive(Clone)]
pub struct SeedEnc {
    bytes: Zeroizing<[u8; Self::BYTES_LEN]>,
}

fn nums_for_words(w: &str) -> Result<[u16; SeedEnc::WORD_COUNT]> {
    let splitwords = w.split(" ").collect::<Vec<_>>();
    if splitwords.len() != SeedEnc::WORD_COUNT {
        bail!(
            "Expected a {} word seed, got {}",
            SeedEnc::WORD_COUNT,
            splitwords.len()
        );
    }
    let mut nums = [0_u16; SeedEnc::WORD_COUNT];
    let mut offending_word = None;
    for lang in words::LANGUAGES {
        for (word, i) in splitwords.iter().zip(0..) {
            if let Some(n) = lang.num_for_word(word) {
                nums[i] = n;
                if i == SeedEnc::WORD_COUNT - 1 {
                    return Ok(nums);
                }
            } else {
                offending_word = Some(word);
                break;
            }
        }
    }
    bail!(
        "No language could be found which matched: {:?} in languages: {:?}",
        offending_word,
        words::LANGUAGES.iter().map(|l|l.name).collect::<Vec<_>>()
    );
}


// I can't believe this is not part of std. No, I'm not pulling in a dep for this.
fn date_from_ts(ts: u64) -> std::time::SystemTime {
    use std::ops::Add;
    std::time::SystemTime::UNIX_EPOCH.add(std::time::Duration::from_secs(ts))
}

impl SeedEnc {
    /// July 7th, 2020, the time when this seed algorithm was first released.
    /// Seeds claiming a birthday older than this should be considered to be almost
    /// certainly invalid - i.e. the password decryption failed.
    const BEGINNING_OF_TIME: u64 = 1586276691;

    /// Output the words which represent this seed
    pub fn words(&self, lang_name: &str) -> Result<String> {
        if let Some(lang) = words::language(lang_name) {
            let mut words = [""; Self::WORD_COUNT];
            for (n, i) in self.nums().iter().zip(0..) {
                words[i] = lang.word_for_num(*n).unwrap();
            }
            Ok(words.join(" "))
        } else {
            bail!("Language {} not found", lang_name);
        }
    }
    /// Get a seed from relevant seed words, language is auto-detected
    pub fn from_words(w: &str) -> Result<Self> {
        let nums = nums_for_words(w)?;
        Self::from_nums(nums)
    }
    /// Get the unused/unusable part of the seed
    fn get_unused(&self) -> u8 {
        self.bytes[0] >> 5
    }
    /// Get seed version, only zero currently defined
    fn get_ver(&self) -> u8 {
        (self.bytes[0] >> 1) & 0x0f
    }
    /// Is the seed encrypted with a passphrase?
    pub fn is_encrypted(&self) -> bool {
        self.bytes[0] & 0x01 == 0x01
    }
    /// Decrypt the seed into a Seed form. If is_encrypted() is true then
    /// a passphrase must be specified.
    /// If force is true then the seed will be decrypted even if the birthday is
    /// in the future or from before July 7th 2020, when this algorithm was first
    /// released.
    pub fn decrypt(&self, passphrase: Option<&[u8]>, force: bool) -> Result<Seed> {
        let mut copy = self.clone();
        if passphrase.is_some() && self.is_encrypted() {
            cipher(&mut copy.bytes[2..], passphrase);
        } else if self.is_encrypted() {
            bail!("This seed is encrypted and requires a passphrase to decrypt");
        }
        let out = Seed::new_raw(&copy.bytes[2..]);
        if !force {
            if out.get_bday() < Self::BEGINNING_OF_TIME {
                bail!(concat!(
                    "This seed has a declared birthday of {:?} which is older than the ",
                    "time when this seed algorithm was first created, the password or ",
                    "seed words are probably incorrect, to override this message set force ",
                    "to true."), date_from_ts(out.get_bday()));
            } else if out.get_bday() > now_sec() {
                bail!(concat!(
                    "This seed has a declated birthday of {:?} which is in the future ",
                    "the seed or password protecting it are probably incorrect. To override ",
                    "this message set force to true."), date_from_ts(out.get_bday()));
            }
        }
        Ok(Seed::new_raw(&copy.bytes[2..]))
    }

    ////////////// Internal

    /// Encoded bytes should be this many
    const BYTES_LEN: usize = 21;

    /// Current (only) version
    const VER: u8 = 0;

    /// Value of unused should be this, it is an artifact of how we unpack words using bignum.
    const EXPECT_UNUSED: u8 = 1;

    /// This number of words in the word representation
    const WORD_COUNT: usize = 15;

    fn from_nums(nums: [u16; Self::WORD_COUNT]) -> Result<Self> {
        let mut b = BigUint::one();
        for n in nums.iter().rev() {
            b <<= 11;
            b += *n;
        }
        let bytes = b.to_bytes_be();
        if bytes.len() != Self::BYTES_LEN {
            bail!("invalid seed: unexpected byte length");
        }
        let mut out = SeedEnc {
            bytes: Zeroizing::new([0_u8; Self::BYTES_LEN]),
        };
        out.bytes.copy_from_slice(&bytes[..]);
        if out.get_unused() != Self::EXPECT_UNUSED {
            bail!("Invalid seed: Wrong bit pattern");
        }
        // After unpacking, the unused must be set to zero for checksum
        out.put_unused(0);
        if out.get_ver() != Self::VER {
            bail!("Invalid seed: Unknown version [{}]", out.get_ver())
        }
        if out.get_csum() != out.compute_csum() {
            bail!(
                "Invalid seed: Checksum mismatch: Declared: [{}], Computed: [{}]",
                out.get_csum(),
                out.compute_csum()
            )
        }
        Ok(out)
    }
    fn nums(&self) -> [u16; Self::WORD_COUNT] {
        let mut copy = self.clone();
        copy.put_unused(Self::EXPECT_UNUSED);
        let mut b = BigUint::from_bytes_be(&copy.bytes[..]);
        let mut out = [0_u16; Self::WORD_COUNT];
        for i in 0..Self::WORD_COUNT {
            out[i] = (b.iter_u32_digits().next().unwrap() & 2047) as u16;
            b >>= 11;
        }
        assert!(b.is_one());
        out
    }
    fn put_unused(&mut self, u: u8) {
        self.bytes[0] &= 31;
        self.bytes[0] |= u << 5;
    }
    fn put_ver(&mut self, v: u8) {
        self.bytes[0] = (self.bytes[0] & 0x01) | ((v & 0x0f) << 1);
    }
    fn put_encrypted(&mut self, e: bool) {
        self.bytes[0] &= 0x1e;
        if e {
            self.bytes[0] |= 0x01
        }
    }
    fn get_csum(&self) -> u8 {
        self.bytes[1]
    }
    fn put_csum(&mut self, csum: u8) {
        self.bytes[1] = csum;
    }
    fn compute_csum(&self) -> u8 {
        let mut b2b = blake2b_simd::Params::new().hash_length(32).to_state();
        // Compute checksum with checksum byte cleared
        let mut copy = self.clone();
        copy.put_csum(0);
        b2b.update(&copy.bytes[..]);
        let res = b2b.finalize();
        res.as_bytes()[0]
    }
}

fn now_sec() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// The salt is fixed because:
/// 1. The password should normally be a strong one
/// 2. Wallet seeds are something one is unlikely to encounter in large quantity
/// 3. The resulting seed must be compact
const ARGON_SALT: &[u8] = b"pktwallet seed 0";

const ARGON_ITERATIONS: u32 = 32;
const ARGON_THREADS: u32 = 8;
const ARGON_MEMORY: u32 = 256 * 1024; // 256k
const ARGON_HASH_LEN: u32 = 19;

fn cipher(data: &mut [u8], passphrase: Option<&[u8]>) {
    if let Some(passphrase) = passphrase {
        // let mut hasher = argonautica::Hasher::default();
        // let output = hasher
        //     .configure_iterations(ARGON_ITERATIONS)
        //     .configure_lanes(ARGON_THREADS)
        //     .configure_memory_size(ARGON_MEMORY)
        //     .configure_hash_len(ARGON_HASH_LEN)
        //     .opt_out_of_secret_key(true)
        //     .with_salt(ARGON_SALT)
        //     .with_password(passphrase)
        //     .hash_raw()
        //     .unwrap();
        // let hash = output.raw_hash_bytes();

        let hash = argon2::hash_raw(passphrase, ARGON_SALT, &argon2::Config{
            ad: &[],
            hash_length: ARGON_HASH_LEN,
            lanes: ARGON_THREADS,
            mem_cost: ARGON_MEMORY,
            secret: &[],
            thread_mode: argon2::ThreadMode::Parallel,
            time_cost: ARGON_ITERATIONS,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        }).unwrap();

        for i in 0..data.len() {
            data[i] ^= hash[i];
        }
    }
}

/// An internal representation of a wallet seed.
/// This contains 19 bytes of entropy, 17 of these bytes are pure random data
/// and two of them represent the seed's "birthday", i.e. the day when the seed
/// was first created.
/// By including a "birthday" in the seed, wallet implementations can avoid scanning
/// the entire history of the blockchain to look for transactions when the wallet may
/// have been paid. The birthday bytes are also used as entropy.
#[derive(Clone)]
pub struct Seed {
    pub bytes: Zeroizing<[u8; Self::BYTES_LEN]>,
}

impl Seed {
    /// Length of the seed bytes
    pub const BYTES_LEN: usize = 19;

    /// Create new seed, birthday is now, input must be 17 bytes
    pub fn new(bytes: &[u8]) -> Self {
        Self::new_bday(bytes, now_sec())
    }
    /// Create new seed with birthday specified, input must be 17 bytes
    pub fn new_bday(bytes: &[u8], birthday: u64) -> Self {
        let mut out = Self {
            bytes: Zeroizing::new([0_u8; Self::BYTES_LEN]),
        };
        out.bytes[2..].copy_from_slice(bytes);
        out.put_bday(birthday);
        out
    }
    /// Birthday is included in the bytes, input must be 19 bytes
    pub fn new_raw(bytes: &[u8]) -> Self {
        let mut out = Self {
            bytes: Zeroizing::new([0_u8; Self::BYTES_LEN]),
        };
        out.bytes.copy_from_slice(bytes);
        out
    }
    /// Returns unix time seconds since the epoch
    pub fn get_bday(&self) -> u64 {
        let mut bday_bytes = [0_u8; 2];
        bday_bytes.copy_from_slice(&self.bytes[0..2]);
        let day = u16::from_be_bytes(bday_bytes);
        (day as u64) * 60 * 60 * 24
    }
    /// Set the seed's birthday, unix seconds since the epoch, this is rounded to nearest day
    pub fn put_bday(&mut self, unix: u64) {
        let day_bytes = ((unix / (60 * 60 * 24)) as u16).to_be_bytes();
        self.bytes[0..2].copy_from_slice(&day_bytes[..]);
    }
    /// If passphrase is specified then this will encrypt the seed, otherwise just
    /// copy it into the form from which seed words can be exported.
    pub fn encrypt(&self, passphrase: Option<&[u8]>) -> SeedEnc {
        let mut out = SeedEnc {
            bytes: Zeroizing::new([0_u8; SeedEnc::BYTES_LEN]),
        };
        out.bytes[2..].copy_from_slice(&self.bytes[..]);
        cipher(&mut out.bytes[2..], passphrase);
        out.put_ver(SeedEnc::VER);
        out.put_encrypted(passphrase.is_some());
        out.put_csum(out.compute_csum());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Seed;
    use super::SeedEnc;
    use anyhow::Result;
    const WORDS: &str =
        "mom blanket bulk draw clip wolf bread erupt merry skin cable infant word exchange animal";
    const BDAY: u64 = 1629936000;
    const SECRET_HEX: &str = "49b1ad8001b3c4813d50c087c5a4e206aeb111";
    const SEED_PASS: &[u8] = b"password";

    #[test]
    fn test_vec() -> Result<()> {
        let se = SeedEnc::from_words(WORDS)?;
        let seed = se.decrypt(Some(SEED_PASS), false)?;
        let seed_hex = hex::encode(&seed.bytes[..]);
        assert_eq!(seed.get_bday(), BDAY);
        assert_eq!(seed_hex, SECRET_HEX);
        Ok(())
    }

    #[test]
    fn test_nums_from_words() -> Result<()> {
        let expect_nums = [
            1142_u16, 186, 240, 531, 346, 2022, 219, 615, 1117, 1620, 255, 922, 2027, 629, 72,
        ];
        let nums = super::nums_for_words(WORDS)?;
        assert_eq!(nums, expect_nums);
        Ok(())
    }

    #[test]
    fn test_enc_from_words() -> Result<()> {
        let se = SeedEnc::from_words(WORDS)?;
        let seed_hex = hex::encode(&se.bytes[..]);
        println!("seed_enc_hex = {}", seed_hex);
        assert_eq!(seed_hex, "01213afeb7343ff2a45d4ce36ff315a4263c05d476");
        Ok(())
    }

    #[test]
    fn test_dec_to_words() {
        let seed = Seed::new_raw(&hex::decode(SECRET_HEX).unwrap()[..]);
        let se = seed.encrypt(Some(SEED_PASS));
        assert_eq!(se.words("english").unwrap(), WORDS);
    }
}
