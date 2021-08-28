#ifndef PKTSEED_H
#define PKTSEED_H

// This file is generated from src/capi.rs using cbindgen

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Return value when everything is ok
 */
#define PKTSEED_RET_OK 0

/**
 * Invalid seed words (not parsable as a string)
 */
#define PKTSEED_RET_INVAL_WORDS -1

/**
 * Invalid, misspelled, unrecognized, or not 15 space-separated words
 */
#define PKTSEED_RET_WRONG_WORDS -2

/**
 * Seed indicates that it is encrypted and no passphrase was given
 */
#define PKTSEED_RET_ENCRYPTED_NO_PASS -3

/**
 * Failed to decrypt seed, wrong passphrase ?
 */
#define PKTSEED_RET_FAILED_DECRYPT -4

/**
 * Internal error
 */
#define PKTSEED_RET_INTERNAL -5

/**
 * Output word buffer is too short for words
 */
#define PKTSEED_RET_SHORT -6

/**
 * Specified language is not recognized
 */
#define PKTSEED_RET_INVAL_LANG -7

/**
 * Invalid input, means length of a buffer is not acceptable
 */
#define PKTSEED_RET_INVAL -8

/**
 * Check if a pktseed requires a passphrase to decrypt.
 * @param needs_passphrase: pointer to a uint32_t, set if 1 if passphrase is needed.
 *     Not set at all if there is an error.
 * @param words: the seed words.
 * @return PKTSEED_RET_INVAL_WORDS or PKTSEED_RET_WRONG_WORDS or PKTSEED_RET_OK.
 */
int pktseed_needs_passphrase(uint32_t *needs_passphrase, const char *words);

/**
 * Decrypt a PKT seed from a set of words.
 * @param seed_out: a buffer of at least 19 bytes to hold the result, 19 bytes will be used
 * @param seed_len: length of seed_out buffer, must be at least 19
 * @param birthday_out: A pointer to a uint64_t which will be set to the seed birthday (seconds since the epoch).
 * @param words: The seed words, input, null-terminated
 * @param passphrase_opt: The passphrase for decrypting the seed words or NULL if no passphrase needed.
 * @return
 *     PKTSEED_RET_INVAL if seed_len is too short
 *     PKTSEED_RET_INVAL_WORDS if words are unparsable
 *     PKTSEED_RET_WRONG_WORDS if words cannot be interpreted as a valid seed
 *     PKTSEED_RET_ENCRYPTED_NO_PASS if seed requires a passphrase
 *     PKTSEED_RET_FAILED_DECRYPT failed to decrypt, probably invalid passphrase
 *     PKTSEED_RET_INTERNAL internal error, should not happen
 *     PKTSEED_RET_OK if all goes well
 */
int pktseed_from_words(uint8_t *seed_out,
                       uint32_t seed_len,
                       uint64_t *birthday_out,
                       const char *words,
                       const char *passphrase_opt);

/**
 * Create a new PKT wallet seed.
 * @param seed_out: Pointer to the seed output, must be at least 19 bytes, 19 bytes are used.
 * @param seed_len: Length of seed_out
 * @param rand_in: Pointer to secure random source, must be at least 17 bytes.
 * @param rand_len: Length of rand_in
 * @return
 *     PKTSEED_RET_INVAL if seed_len or rand_len is invalid
 *     PKTSEED_RET_OK if all is well
 */
int pktseed_new(uint8_t *seed_out, uint32_t seed_len, const uint8_t *rand_in, uint32_t rand_len);

/**
 * Convert a PKT wallet seed to seed words.
 * @param words_out: Pointer to a buffer to store words, should be 128 bytes to be safe
 * @param words_len: Length of words_out
 * @param seed: The PKT wallet seed, must be precisely 19 bytes.
 * @param seed_len: The length of seed
 * @param language: The language in which to render the words.
 * @param passphrase_opt: If non-NULL, a passphrase which will be used to encrypt the seed before rendering to words.
 * @return
 *     PKTSEED_RET_INVAL if seed_len is invalid
 *     PKTSEED_RET_INVAL_LANG if language is unknown
 *     PKTSEED_RET_SHORT not enough space to store the seed words in words_out
 *     PKTSEED_RET_OK if all is well
 */
int pktseed_to_words(char *words_out,
                     uint32_t words_len,
                     const uint8_t *seed,
                     uint32_t seed_len,
                     const char *language,
                     const char *passphrase_opt);

#endif /* PKTSEED_H */
