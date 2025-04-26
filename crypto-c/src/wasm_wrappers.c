#include <stdlib.h>
#include <stdio.h>
#include <string.h> // For memcpy, strlen
#include <pbc/pbc.h>
#include "bls_ibe_util.h" // For utilities including buffer deserializers
#include "ibe.h"          // For IBE Encrypt/Decrypt

// Define the path where pairing parameters are expected in the Wasm virtual filesystem
#define WASM_PARAM_FILE "/a.param" // Use leading slash for root directory

// --- Helper Function ---
// Initializes pairing for Wasm environment. Returns 0 on success, 1 on error.
// Assumes WASM_PARAM_FILE exists in Emscripten's virtual FS (MEMFS).
static int initialize_wasm_pairing(pairing_t pairing) {
    // Check if pairing is already initialized (simple check, not thread-safe)
    // if (pairing->G1 != NULL) return 0; // Avoid re-init if possible (needs more robust check)

    FILE *fp = fopen(WASM_PARAM_FILE, "rb");
    if (!fp) {
        fprintf(stderr, "Wasm Error: Pairing parameter file '%s' not found in virtual filesystem.\n", WASM_PARAM_FILE);
        return 1; // Indicate error
    }
    // Read the file content into a buffer for initialize_pairing
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) {
        fprintf(stderr, "Wasm Error: Pairing parameter file '%s' is empty or invalid size.\n", WASM_PARAM_FILE);
        fclose(fp);
        return 1;
    }
    char *param_buf = (char*)malloc(fsize + 1);
    if (!param_buf) {
        fprintf(stderr, "Wasm Error: Failed to allocate buffer for pairing params.\n");
        fclose(fp);
        return 1;
    }
    size_t read_count = fread(param_buf, 1, fsize, fp);
    fclose(fp);
    if (read_count != (size_t)fsize) {
         fprintf(stderr, "Wasm Error: Failed to read pairing parameter file '%s'.\n", WASM_PARAM_FILE);
         free(param_buf);
         return 1;
    }
    param_buf[fsize] = 0; // Null-terminate just in case

    // Use the utility function which now reads from file internally
    // initialize_pairing(pairing, WASM_PARAM_FILE);
    // OR initialize directly from buffer
    if (pairing_init_set_buf(pairing, param_buf, read_count)) {
         fprintf(stderr, "Wasm Error: pairing_init_set_buf failed.\n");
         free(param_buf);
         return 1;
    }
    free(param_buf);

    if (!pairing_is_symmetric(pairing)) {
         fprintf(stderr, "Wasm Error: Pairing must be symmetric (Type A).\n");
         pairing_clear(pairing); // Clean up partially initialized pairing
         return 1;
    }

    return 0; // Success
}


// --- Exported Wasm Functions ---

/**
 * @brief Initializes the user side of non-escrow key generation.
 *
 * Generates the user secret (usk) and the blinding factor (usk_inv).
 * Allocates memory for a buffer containing usk || usk_inv.
 * This buffer must be freed by the caller using wasm_free_buffer().
 *
 * @param user_id Null-terminated string containing the user's identity.
 * @param output_usk_len Pointer to size_t where the length of the usk part will be written.
 * @param output_usk_inv_len Pointer to size_t where the length of the usk_inv part will be written.
 * @param output_total_len Pointer to size_t where the total length of the returned buffer will be written.
 * @return Pointer to the allocated buffer (usk || usk_inv), or NULL on error.
 */
unsigned char* wasm_user_keygen_init(
    const char* user_id,
    size_t* output_usk_len,
    size_t* output_usk_inv_len,
    size_t* output_total_len
) {
    // Null checks for output pointers
    if (!output_usk_len || !output_usk_inv_len || !output_total_len) {
        fprintf(stderr, "Wasm KeygenInit Error: Output length pointers cannot be NULL.\n");
        return NULL;
    }
    *output_usk_len = 0;
    *output_usk_inv_len = 0;
    *output_total_len = 0;

    // Check user_id
     if (!user_id || strlen(user_id) == 0) {
         fprintf(stderr, "Wasm KeygenInit Error: User ID is NULL or empty.\n");
         return NULL;
    }

    pairing_t pairing;
    element_t usk, usk_inv, zero_el;
    unsigned char *output_buffer = NULL;

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return NULL;
    }

    // 2. Initialize elements
    element_init_Zr(usk, pairing);
    element_init_Zr(usk_inv, pairing);
    element_init_Zr(zero_el, pairing);
    element_set0(zero_el);

    // 3. Generate non-zero usk
    do {
        element_random(usk);
    } while (element_cmp(usk, zero_el) == 0);

    // 4. Compute usk_inv
    element_invert(usk_inv, usk);

    // 5. Determine lengths and allocate output buffer
    int usk_len = element_length_in_bytes(usk);
    int usk_inv_len = element_length_in_bytes(usk_inv);
    if (usk_len <= 0 || usk_inv_len <= 0) {
        fprintf(stderr, "Wasm KeygenInit Error: Invalid element lengths (%d, %d).\n", usk_len, usk_inv_len);
        element_clear(usk); element_clear(usk_inv); element_clear(zero_el); pairing_clear(pairing);
        return NULL;
    }
    size_t total_len_calc = (size_t)usk_len + (size_t)usk_inv_len;
    output_buffer = (unsigned char *)malloc(total_len_calc);
    if (!output_buffer) {
        fprintf(stderr, "Wasm KeygenInit Error: Malloc failed for output buffer.\n");
        element_clear(usk); element_clear(usk_inv); element_clear(zero_el); pairing_clear(pairing);
        return NULL;
    }

    // 6. Serialize elements into the buffer
    element_to_bytes(output_buffer, usk);                     // usk at the start
    element_to_bytes(output_buffer + usk_len, usk_inv);       // usk_inv after usk

    // 7. Set output lengths
    *output_usk_len = (size_t)usk_len;
    *output_usk_inv_len = (size_t)usk_inv_len;
    *output_total_len = total_len_calc;

    // 8. Cleanup
    element_clear(usk);
    element_clear(usk_inv);
    element_clear(zero_el);
    pairing_clear(pairing);

    // 9. Return combined buffer
    return output_buffer;
}


/**
 * @brief Finalizes the user side of non-escrow key generation.
 *
 * Combines the user secret (usk) and the partial key from the server (d_partial)
 * to compute the final private key (d_final). Allocates memory for the
 * compressed final key, which must be freed by the caller using wasm_free_buffer().
 *
 * @param user_secret_data Buffer containing the user secret (usk, Zr element).
 * @param user_secret_len Length of the user secret buffer.
 * @param partial_key_data Buffer containing the partial key (d_partial, compressed G1 element).
 * @param partial_key_len Length of the partial key buffer.
 * @param output_final_key_len Pointer to size_t where the length of the returned final key buffer will be written.
 * @return Pointer to the allocated buffer containing the compressed final private key, or NULL on error.
 */
unsigned char* wasm_user_keygen_finalize(
    const unsigned char* user_secret_data, size_t user_secret_len,
    const unsigned char* partial_key_data, size_t partial_key_len,
    size_t* output_final_key_len
) {
     // Null check for output pointer
    if (!output_final_key_len) {
        fprintf(stderr, "Wasm KeygenFinalize Error: output_final_key_len pointer is NULL.\n");
        return NULL;
    }
    *output_final_key_len = 0; // Initialize

    pairing_t pairing;
    element_t usk, d_partial, d_final;
    unsigned char *output_buffer = NULL;

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return NULL;
    }

    // 2. Deserialize user secret (usk)
    if (deserialize_zr_from_buffer(pairing, usk, user_secret_data, user_secret_len) != 0) {
        fprintf(stderr, "Wasm KeygenFinalize Error: Failed to load user secret from buffer.\n");
        pairing_clear(pairing);
        return NULL;
    }

    // 3. Deserialize partial key (d_partial)
    if (deserialize_partial_key_from_buffer(pairing, d_partial, partial_key_data, partial_key_len) != 0) {
        fprintf(stderr, "Wasm KeygenFinalize Error: Failed to load partial key from buffer.\n");
        element_clear(usk); pairing_clear(pairing);
        return NULL;
    }

    // 4. Compute final key: d_final = d_partial ^ usk
    element_init_G1(d_final, pairing);
    element_pow_zn(d_final, d_partial, usk);

    // 5. Determine length and allocate output buffer for compressed final key
    int final_key_len_comp = element_length_in_bytes_compressed(d_final);
    if (final_key_len_comp <= 0) {
        fprintf(stderr, "Wasm KeygenFinalize Error: Invalid final key compressed length (%d).\n", final_key_len_comp);
        element_clear(usk); element_clear(d_partial); element_clear(d_final); pairing_clear(pairing);
        return NULL;
    }
    output_buffer = (unsigned char *)malloc((size_t)final_key_len_comp);
    if (!output_buffer) {
        fprintf(stderr, "Wasm KeygenFinalize Error: Malloc failed for output buffer.\n");
        element_clear(usk); element_clear(d_partial); element_clear(d_final); pairing_clear(pairing);
        return NULL;
    }

    // 6. Serialize compressed final key into the buffer
    element_to_bytes_compressed(output_buffer, d_final);

    // 7. Set output length
    *output_final_key_len = (size_t)final_key_len_comp;

    // 8. Cleanup
    element_clear(usk);
    element_clear(d_partial);
    element_clear(d_final);
    pairing_clear(pairing);

    // 9. Return final key buffer
    return output_buffer;
}


// --- wasm_sign_buffer, wasm_encrypt_buffer, wasm_decrypt_buffer, wasm_verify_buffer ---
// --- (Keep the existing implementations from the previous answer) ---
// --- Make sure they use the new deserialize helpers correctly ---

/**
 * @brief Signs a message using a provided private key.
 * Allocates memory for the signature which must be freed by the caller using wasm_free_buffer().
 * ... (rest of function as before, ensure it uses deserialize_private_key_from_buffer) ...
 */
unsigned char* wasm_sign_buffer(
    const unsigned char* private_key_data, size_t private_key_len,
    const unsigned char* message_data, size_t message_len,
    size_t* output_sig_len
) {
    // ... (Implementation as before, using deserialize_private_key_from_buffer) ...
    pairing_t pairing;
    element_t d;       // User's private key
    element_t h;       // Hash of message
    element_t sigma;   // Signature
    unsigned char *sig_bytes_out = NULL; // Pointer to return

    if (!output_sig_len) { fprintf(stderr, "Wasm Sign Error: output_sig_len pointer is NULL.\n"); return NULL; }
    *output_sig_len = 0;

    if (initialize_wasm_pairing(pairing) != 0) return NULL;

    // Use the specific deserializer
    if (deserialize_private_key_from_buffer(pairing, d, private_key_data, private_key_len) != 0) {
        fprintf(stderr, "Wasm Sign Error: Failed to load private key from buffer.\n");
        pairing_clear(pairing);
        return NULL;
    }

    hash_message_to_Zr(h, message_data, message_len, pairing);
    element_init_G1(sigma, pairing);
    element_pow_zn(sigma, d, h);

    int sig_len = element_length_in_bytes_compressed(sigma);
    if (sig_len <= 0) {
         fprintf(stderr, "Wasm Sign Error: Failed to get signature length.\n");
         element_clear(d); element_clear(h); element_clear(sigma); pairing_clear(pairing);
         return NULL;
    }
    *output_sig_len = (size_t)sig_len;

    sig_bytes_out = (unsigned char *)malloc(*output_sig_len);
    if (!sig_bytes_out) {
        fprintf(stderr, "Wasm Sign Error: Malloc failed for signature buffer.\n");
        element_clear(d); element_clear(h); element_clear(sigma); pairing_clear(pairing);
        return NULL;
    }
    element_to_bytes_compressed(sig_bytes_out, sigma);

    element_clear(d); element_clear(h); element_clear(sigma); pairing_clear(pairing);
    return sig_bytes_out;
}

/**
 * @brief Encrypts a message and signature for a recipient ID using IBE.
 * Allocates memory for the ciphertext (U||V) which must be freed by the caller using wasm_free_buffer().
 * ... (rest of function as before, ensure it uses deserialize_public_params_from_buffer) ...
 */
unsigned char* wasm_encrypt_buffer(
    const unsigned char* pub_params_data, size_t pub_params_len,
    const char* receiver_id,
    const unsigned char* message_data, size_t message_len,
    const unsigned char* signature_data, size_t signature_len,
    size_t* output_u_len,
    size_t* output_total_len
) {
    // ... (Implementation as before, using deserialize_public_params_from_buffer) ...
     if (!output_u_len || !output_total_len) { fprintf(stderr, "Wasm Encrypt Error: Output length pointers cannot be NULL.\n"); return NULL; }
    *output_u_len = 0; *output_total_len = 0;

    pairing_t pairing;
    element_t g, P_pub, U;
    unsigned char *plaintext_buffer = NULL, *V = NULL, *output_buffer = NULL;

    if (initialize_wasm_pairing(pairing) != 0) return NULL;

    // Use the specific deserializer
    if (deserialize_public_params_from_buffer(pairing, g, P_pub, pub_params_data, pub_params_len) != 0) {
        fprintf(stderr, "Wasm Encrypt Error: Failed to load public params from buffer.\n");
        pairing_clear(pairing);
        return NULL;
    }

    size_t plaintext_len = message_len + signature_len;
     if (plaintext_len == 0 && (message_len > 0 || signature_len > 0)) {
         fprintf(stderr, "Wasm Encrypt Error: Plaintext length calculation overflow or invalid input lengths.\n");
         element_clear(g); element_clear(P_pub); pairing_clear(pairing); return NULL;
     }
     if (plaintext_len == 0) { // Handle empty encryption if needed, returning NULL for now
         fprintf(stderr, "Wasm Encrypt Warning: Plaintext length is zero.\n");
         element_clear(g); element_clear(P_pub); pairing_clear(pairing); return NULL;
     }

    plaintext_buffer = (unsigned char *)malloc(plaintext_len);
    if (!plaintext_buffer) { /* handle error */ element_clear(g); element_clear(P_pub); pairing_clear(pairing); return NULL; }
    memcpy(plaintext_buffer, message_data, message_len);
    memcpy(plaintext_buffer + message_len, signature_data, signature_len);

    element_init_G1(U, pairing);
    V = (unsigned char *)malloc(plaintext_len);
    if (!V) { /* handle error */ free(plaintext_buffer); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing); return NULL; }

    Encrypt(pairing, g, P_pub, receiver_id, plaintext_buffer, plaintext_len, U, V);

    int U_len_comp = element_length_in_bytes_compressed(U);
     if (U_len_comp <= 0) { /* handle error */ free(plaintext_buffer); free(V); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing); return NULL; }

    *output_u_len = (size_t)U_len_comp;
    *output_total_len = (size_t)U_len_comp + plaintext_len;

    output_buffer = (unsigned char *)malloc(*output_total_len);
    if (!output_buffer) { /* handle error */ *output_u_len = 0; *output_total_len = 0; free(plaintext_buffer); free(V); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing); return NULL; }

    element_to_bytes_compressed(output_buffer, U);
    memcpy(output_buffer + U_len_comp, V, plaintext_len);

    free(plaintext_buffer); free(V);
    element_clear(g); element_clear(P_pub); element_clear(U);
    pairing_clear(pairing);

    return output_buffer;
}

/**
 * @brief Decrypts an IBE ciphertext (U||V) using the recipient's private key.
 * Allocates memory for the plaintext (message||signature) which must be freed by the caller using wasm_free_buffer().
 * ... (rest of function as before, ensure it uses correct deserializers) ...
 */
unsigned char* wasm_decrypt_buffer(
    const unsigned char* private_key_data, size_t private_key_len,
    const unsigned char* u_data, size_t u_len,
    const unsigned char* v_data, size_t v_len,
    size_t* output_plaintext_len
) {
    // ... (Implementation as before, using deserialize_private_key_from_buffer and deserialize_ciphertext_u_from_buffer) ...
    if (!output_plaintext_len) { fprintf(stderr, "Wasm Decrypt Error: output_plaintext_len pointer is NULL.\n"); return NULL; }
    *output_plaintext_len = 0;

    pairing_t pairing;
    element_t d_receiver, U;
    unsigned char *plaintext_buffer = NULL;

    if (initialize_wasm_pairing(pairing) != 0) return NULL;

    if (deserialize_private_key_from_buffer(pairing, d_receiver, private_key_data, private_key_len) != 0) {
        fprintf(stderr, "Wasm Decrypt Error: Failed to load private key from buffer.\n");
        pairing_clear(pairing); return NULL;
    }

    if (deserialize_ciphertext_u_from_buffer(pairing, U, u_data, u_len) != 0) {
        fprintf(stderr, "Wasm Decrypt Error: Failed to load U from buffer.\n");
        element_clear(d_receiver); pairing_clear(pairing); return NULL;
    }

     if (v_len == 0) {
        fprintf(stderr, "Wasm Decrypt Error: Ciphertext V part has zero length.\n");
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing); return NULL;
    }
    plaintext_buffer = (unsigned char *)malloc(v_len);
    if (!plaintext_buffer) { /* handle error */ element_clear(d_receiver); element_clear(U); pairing_clear(pairing); return NULL; }

    Decrypt(pairing, d_receiver, U, v_data, v_len, plaintext_buffer);

    *output_plaintext_len = v_len;
    element_clear(d_receiver); element_clear(U); pairing_clear(pairing);

    return plaintext_buffer;
}

/**
 * @brief Verifies a signature against a message and signer's identity.
 * @return 0 if signature is VALID, 1 if signature is INVALID, -1 on error.
 * ... (rest of function as before, ensure it uses correct deserializers) ...
 */
int wasm_verify_buffer(
    const unsigned char* pub_params_data, size_t pub_params_len,
    const char* signer_id,
    const unsigned char* message_data, size_t message_len,
    const unsigned char* signature_data, size_t signature_len
) {
    // ... (Implementation as before, using deserialize_public_params_from_buffer and deserialize_signature_from_buffer) ...
    pairing_t pairing;
    element_t g, P_pub, Q_signer, h, sigma;
    element_t temp_G1, lhs_GT, rhs_GT;
    int result = -1;

    if (initialize_wasm_pairing(pairing) != 0) return -1;

    if (deserialize_public_params_from_buffer(pairing, g, P_pub, pub_params_data, pub_params_len) != 0) {
        fprintf(stderr, "Wasm Verify Error: Failed to load public params from buffer.\n");
        pairing_clear(pairing); return -1;
    }

    if (deserialize_signature_from_buffer(pairing, sigma, signature_data, signature_len) != 0) {
        fprintf(stderr, "Wasm Verify Error: Failed to load signature from buffer.\n");
        element_clear(g); element_clear(P_pub); pairing_clear(pairing); return -1;
    }

     if (!signer_id || strlen(signer_id) == 0) {
         fprintf(stderr, "Wasm Verify Error: Signer ID is NULL or empty.\n");
         element_clear(g); element_clear(P_pub); element_clear(sigma); pairing_clear(pairing); return -1;
     }
    hash_id_to_G1(Q_signer, signer_id, pairing);
    hash_message_to_Zr(h, message_data, message_len, pairing);

    element_init_GT(lhs_GT, pairing);
    pairing_apply(lhs_GT, sigma, g, pairing);

    element_init_G1(temp_G1, pairing);
    element_pow_zn(temp_G1, Q_signer, h);

    element_init_GT(rhs_GT, pairing);
    pairing_apply(rhs_GT, temp_G1, P_pub, pairing);

    if (!element_cmp(lhs_GT, rhs_GT)) { result = 0; } else { result = 1; }

    element_clear(g); element_clear(P_pub); element_clear(Q_signer); element_clear(h);
    element_clear(sigma); element_clear(temp_G1); element_clear(lhs_GT); element_clear(rhs_GT);
    pairing_clear(pairing);

    return result;
}


/**
 * @brief Frees memory allocated by Wasm functions (like wasm_sign_buffer).
 * Should be called from JavaScript to free the pointers returned by functions
 * that allocate memory internally using malloc().
 * @param ptr Pointer to the memory buffer to free.
 */
void wasm_free_buffer(void* ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}