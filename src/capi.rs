// SPDX-License-Identifier: MIT OR Apache-2.0
use std::os::raw::c_int;
use std::ffi::CStr;
use std::os::raw::c_char;
use crate::{Seed, SeedEnc};

/// Return value when everything is ok
pub const PKTSEED_RET_OK: c_int = 0;

/// Invalid seed words (not parsable as a string)
pub const PKTSEED_RET_INVAL_WORDS: c_int = -1;

/// Invalid, misspelled, unrecognized, or not 15 space-separated words
pub const PKTSEED_RET_WRONG_WORDS: c_int = -2;

/// Seed indicates that it is encrypted and no passphrase was given
pub const PKTSEED_RET_ENCRYPTED_NO_PASS: c_int = -3;

/// Failed to decrypt seed, wrong passphrase ?
pub const PKTSEED_RET_FAILED_DECRYPT: c_int = -4;

/// Internal error
pub const PKTSEED_RET_INTERNAL: c_int = -5;

/// Output word buffer is too short for words
pub const PKTSEED_RET_SHORT: c_int = -6;

/// Specified language is not recognized
pub const PKTSEED_RET_INVAL_LANG: c_int = -7;

/// Invalid input, means length of a buffer is not acceptable
pub const PKTSEED_RET_INVAL: c_int = -8;

/// Check if a pktseed requires a passphrase to decrypt.
/// @param needs_passphrase: pointer to a uint32_t, set if 1 if passphrase is needed.
///     Not set at all if there is an error.
/// @param words: the seed words.
/// @return PKTSEED_RET_INVAL_WORDS or PKTSEED_RET_WRONG_WORDS or PKTSEED_RET_OK.
#[no_mangle]
pub unsafe extern "C" fn pktseed_needs_passphrase(
    needs_passphrase: *mut u32,
    words: *const c_char,
) -> c_int {
    let words_s = if let Ok(ws) = CStr::from_ptr(words).to_str() {
        ws
    } else {
        return PKTSEED_RET_INVAL_WORDS;
    };
    let se = if let Ok(w) = SeedEnc::from_words(words_s) {
        w
    } else {
        return PKTSEED_RET_WRONG_WORDS;
    };
    *needs_passphrase = if se.is_encrypted() {
        1
    } else {
        0
    };
    PKTSEED_RET_OK
}

/// Decrypt a PKT seed from a set of words.
/// @param seed_out: a buffer of at least 19 bytes to hold the result, 19 bytes will be used
/// @param seed_len: length of seed_out buffer, must be at least 19
/// @param birthday_out: A pointer to a uint64_t which will be set to the seed birthday (seconds since the epoch).
/// @param words: The seed words, input, null-terminated
/// @param passphrase_opt: The passphrase for decrypting the seed words or NULL if no passphrase needed.
/// @return
///     PKTSEED_RET_INVAL if seed_len is too short
///     PKTSEED_RET_INVAL_WORDS if words are unparsable
///     PKTSEED_RET_WRONG_WORDS if words cannot be interpreted as a valid seed
///     PKTSEED_RET_ENCRYPTED_NO_PASS if seed requires a passphrase
///     PKTSEED_RET_FAILED_DECRYPT failed to decrypt, probably invalid passphrase
///     PKTSEED_RET_INTERNAL internal error, should not happen
///     PKTSEED_RET_OK if all goes well
#[no_mangle]
pub unsafe extern "C" fn pktseed_from_words(
    seed_out: *mut u8,
    seed_len: u32,
    birthday_out: *mut u64,
    words: *const c_char,
    passphrase_opt: *const c_char,
) -> c_int {
    if seed_len < Seed::BYTES_LEN as u32 {
        return PKTSEED_RET_INVAL;
    }
    let so = std::slice::from_raw_parts_mut(seed_out, Seed::BYTES_LEN);
    let words_s = if let Ok(ws) = CStr::from_ptr(words).to_str() {
        ws
    } else {
        return PKTSEED_RET_INVAL_WORDS;
    };
    let passphrase = if passphrase_opt.is_null() {
        None
    } else {
        Some(CStr::from_ptr(passphrase_opt).to_bytes())
    };
    let se = if let Ok(w) = SeedEnc::from_words(words_s) {
        w
    } else {
        return PKTSEED_RET_WRONG_WORDS;
    };
    let seed = if se.is_encrypted() {
        if passphrase.is_none() {
            return PKTSEED_RET_ENCRYPTED_NO_PASS;
        }
        if let Ok(seed) = se.decrypt(passphrase) {
            seed
        } else {
            return PKTSEED_RET_FAILED_DECRYPT;
        }
    } else {
        if let Ok(seed) = se.decrypt(None) {
            seed
        } else {
            return PKTSEED_RET_INTERNAL
        }
    };
    so.copy_from_slice(&seed.bytes[..]);
    *birthday_out = seed.get_bday();
    PKTSEED_RET_OK
}

/// Create a new PKT wallet seed.
/// @param seed_out: Pointer to the seed output, must be at least 19 bytes, 19 bytes are used.
/// @param seed_len: Length of seed_out
/// @param rand_in: Pointer to secure random source, must be at least 17 bytes.
/// @param rand_len: Length of rand_in
/// @return
///     PKTSEED_RET_INVAL if seed_len or rand_len is invalid
///     PKTSEED_RET_OK if all is well
#[no_mangle]
pub unsafe extern "C" fn pktseed_new(
    seed_out: *mut u8,
    seed_len: u32,
    rand_in: *const u8,
    rand_len: u32,
) -> c_int {
    if seed_len < Seed::BYTES_LEN as u32 {
        return PKTSEED_RET_INVAL;
    }
    if rand_len < (Seed::BYTES_LEN - 2) as u32 {
        return PKTSEED_RET_INVAL;
    }
    let in_bytes = std::slice::from_raw_parts(rand_in, Seed::BYTES_LEN - 2);
    let out_bytes = std::slice::from_raw_parts_mut(seed_out, Seed::BYTES_LEN);
    let s = Seed::new(in_bytes);
    out_bytes.copy_from_slice(&s.bytes[..]);
    PKTSEED_RET_OK
}

/// Convert a PKT wallet seed to seed words.
/// @param words_out: Pointer to a buffer to store words, should be 128 bytes to be safe
/// @param words_len: Length of words_out
/// @param seed: The PKT wallet seed, must be precisely 19 bytes.
/// @param seed_len: The length of seed
/// @param language: The language in which to render the words.
/// @param passphrase_opt: If non-NULL, a passphrase which will be used to encrypt the seed before rendering to words.
/// @return
///     PKTSEED_RET_INVAL if seed_len is invalid
///     PKTSEED_RET_INVAL_LANG if language is unknown
///     PKTSEED_RET_SHORT not enough space to store the seed words in words_out
///     PKTSEED_RET_OK if all is well
#[no_mangle]
pub unsafe extern "C" fn pktseed_to_words(
    words_out: *mut c_char,
    words_len: u32,
    seed: *const u8,
    seed_len: u32,
    language: *const c_char,
    passphrase_opt: *const c_char,
) -> c_int {
    if seed_len != Seed::BYTES_LEN as u32 {
        return PKTSEED_RET_INVAL;
    }
    let passphrase = if passphrase_opt.is_null() {
        None
    } else {
        Some(CStr::from_ptr(passphrase_opt).to_bytes())
    };
    let seed_bytes = std::slice::from_raw_parts(seed, Seed::BYTES_LEN);
    let seed = Seed::new_raw(&seed_bytes[..]);
    let seed_enc = seed.encrypt(passphrase);
    let lang = CStr::from_ptr(language).to_str().unwrap();
    let words = if let Ok(se) = seed_enc.words(lang) {
        se
    } else {
        return PKTSEED_RET_INVAL_LANG;
    };
    if words_len < (words.as_bytes().len() + 1) as u32 {
        return PKTSEED_RET_SHORT;
    }
    let wo = std::slice::from_raw_parts_mut(words_out as *mut u8, words.as_bytes().len() + 1);
    wo.copy_from_slice(words.as_bytes());
    wo[wo.len() - 1] = 0;
    PKTSEED_RET_OK
}