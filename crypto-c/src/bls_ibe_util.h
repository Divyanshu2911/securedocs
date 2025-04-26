#ifndef BLS_IBE_UTIL_H
#define BLS_IBE_UTIL_H

#include <pbc/pbc.h>
#include <openssl/sha.h> // For SHA256
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> // For size_t

/* --- Error Handling --- */
// Using exit() might not be ideal in library code, consider returning errors instead.
#define DIE(msg) \
    do { perror(msg); fprintf(stderr, "Fatal error: %s\n", msg); exit(EXIT_FAILURE); } while (0)

/* --- File Operations (Keep for Native/Testing) --- */

// Reads the entire content of a file into a newly allocated buffer.
// Returns NULL on error or if file is empty. Caller must free the buffer.
unsigned char* read_file_content(const char *filename, size_t *len);

// Writes data to a file. Exits on failure using DIE.
void write_file_content(const char *filename, const unsigned char *data, size_t len);

/* --- PBC Initialization --- */

// Initializes pairing from a parameter file. Exits on failure using DIE.
void initialize_pairing(pairing_t pairing, const char *param_file);

/* --- File-Based Loading/Saving (Keep for Native/Testing/Server) --- */

// Loads public parameters (g, P_pub) from a file. Exits on failure.
void load_public_params(pairing_t pairing, element_t g, element_t P_pub, const char *filename);

// Loads master secret key (msk) from a file. Exits on failure.
void load_master_secret(pairing_t pairing, element_t msk, const char *filename);

// Loads user private key (compressed G1) from a file. Exits on failure.
void load_user_private_key(pairing_t pairing, element_t user_sk, const char *filename);

// Saves user private key (compressed G1) to a file. Exits on failure.
void save_user_private_key(element_t user_sk, const char *filename);

// Loads a Zr element from a file. Exits on failure.
void load_zr_element(pairing_t pairing, element_t zr_val, const char *filename);

// Saves a Zr element to a file. Exits on failure.
void save_zr_element(element_t zr_val, const char *filename);

// Define aliases for partial key file operations (uses G1 format)
#define save_partial_key save_user_private_key
#define load_partial_key load_user_private_key

/* --- Hashing Functions --- */

// Hashes an ID string into a G1 element Q. Initializes Q.
void hash_id_to_G1(element_t Q, const char *id, pairing_t pairing);

// Hashes a message buffer into a Zr element h. Initializes h.
void hash_message_to_Zr(element_t h, const unsigned char *msg, size_t msg_len, pairing_t pairing);

/* --- Wasm Buffer Serialization/Deserialization Helpers --- */

// Deserialize compressed G1 element (e.g., private key, partial key, signature, U)
// Initializes el_g1. Returns 0 on success, non-zero on error.
int deserialize_g1_compressed_from_buffer(
    pairing_t pairing,
    element_t el_g1,
    const unsigned char* buffer,
    size_t buffer_len
);

// Deserialize Zr element
// Initializes el_zr. Returns 0 on success, non-zero on error.
int deserialize_zr_from_buffer(
    pairing_t pairing,
    element_t el_zr,
    const unsigned char* buffer,
    size_t buffer_len
);

// Deserialize public parameters (compressed g || compressed P_pub)
// Initializes g and P_pub. Returns 0 on success, non-zero on error.
int deserialize_public_params_from_buffer(
    pairing_t pairing,
    element_t g,
    element_t P_pub,
    const unsigned char* buffer,
    size_t buffer_len
);

// Convenience macros (assuming keys/sigs/U are compressed G1)
#define deserialize_private_key_from_buffer deserialize_g1_compressed_from_buffer
#define deserialize_partial_key_from_buffer deserialize_g1_compressed_from_buffer
#define deserialize_signature_from_buffer deserialize_g1_compressed_from_buffer
#define deserialize_ciphertext_u_from_buffer deserialize_g1_compressed_from_buffer

#endif // BLS_IBE_UTIL_H