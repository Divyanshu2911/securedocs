#include "bls_ibe_util.h"
#include <errno.h> // For checking file operation errors more granularly

/* --- File Operations Implementation --- */

unsigned char* read_file_content(const char *filename, size_t *len) {
    // Ensure len pointer is valid
    if (!len) {
        fprintf(stderr, "Error: len pointer is NULL in read_file_content.\n");
        return NULL;
    }
    *len = 0; // Initialize length to 0

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        // Don't use DIE here, allow caller to handle missing files gracefully
        // fprintf(stderr, "Warning: Cannot open file '%s' for reading: %s\n", filename, strerror(errno));
        perror("read_file_content fopen");
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("read_file_content fseek SEEK_END");
        fclose(fp);
        return NULL;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        perror("read_file_content ftell");
        fclose(fp);
        return NULL;
    }
    // Check for excessively large files if necessary
    // if (file_size > SOME_MAX_SIZE) { ... }

    *len = (size_t)file_size;
    if (fseek(fp, 0, SEEK_SET) != 0) { // rewind alternative
         perror("read_file_content fseek SEEK_SET");
         fclose(fp);
         return NULL;
    }

    // Handle zero-length file - return NULL, caller checks *len
    if (*len == 0) {
        fclose(fp);
        return NULL;
    }

    unsigned char *buffer = (unsigned char *)malloc(*len);
    if (!buffer) {
        fprintf(stderr, "Malloc failed in read_file_content for size %zu\n", *len);
        fclose(fp);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, *len, fp);
    if (bytes_read != *len) {
        // Check for read error vs EOF (though EOF shouldn't happen here)
        if (ferror(fp)) {
             perror("read_file_content fread");
        } else {
             fprintf(stderr, "Read error in read_file_content: read %zu bytes, expected %zu from file: %s\n", bytes_read, *len, filename);
        }
        free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    return buffer;
}

void write_file_content(const char *filename, const unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    // Check if data is NULL even if len is 0, fopen could still fail
    if (!fp) {
        fprintf(stderr, "Failed to open file '%s' for writing", filename);
        DIE(": fopen failed"); // Using DIE for simplicity here
    }

    // Only write if there's data and length is non-zero
    if (data != NULL && len > 0) {
        if (fwrite(data, 1, len, fp) != len) {
            fclose(fp);
            fprintf(stderr, "Failed to write complete data (%zu bytes) to file '%s'", len, filename);
            DIE(": fwrite failed");
        }
    }
    // If len is 0 or data is NULL, we just create/truncate the file.

    if (fclose(fp) != 0) {
         DIE("Failed to close file after writing");
    }
}

/* --- PBC Initialization Implementation --- */

void initialize_pairing(pairing_t pairing, const char *param_file) {
    size_t param_len;
    unsigned char *param_buf = read_file_content(param_file, &param_len);
    if (!param_buf || param_len == 0) {
        fprintf(stderr, "Fatal: Failed to read pairing parameters from '%s'\n", param_file);
        exit(EXIT_FAILURE);
    }

    if (pairing_init_set_buf(pairing, (const char *)param_buf, param_len)) {
        free(param_buf);
        fprintf(stderr, "Fatal: Pairing initialization failed\n");
        exit(EXIT_FAILURE);
    }
    free(param_buf); // Free buffer after successful initialization

    if (!pairing_is_symmetric(pairing)) {
        fprintf(stderr, "Fatal Error: Pairing must be symmetric (Type A) for this scheme.\n");
        // pairing_clear(pairing); // Consider clearing if needed before exit
        exit(EXIT_FAILURE);
    }
     // fprintf(stderr, "Pairing initialized successfully.\n"); // Optional debug
}

/* --- File-Based Loading/Saving Implementation --- */

void load_public_params(pairing_t pairing, element_t g, element_t P_pub, const char *filename) {
    size_t buffer_len;
    unsigned char *buffer = read_file_content(filename, &buffer_len);
     if (!buffer || buffer_len == 0) {
        fprintf(stderr, "Fatal: Failed to read public parameters from '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    // Use the buffer deserialization function
    if (deserialize_public_params_from_buffer(pairing, g, P_pub, buffer, buffer_len) != 0) {
        free(buffer);
        fprintf(stderr, "Fatal: Failed to parse public parameters from file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    free(buffer); // Free buffer after successful deserialization
}

void load_master_secret(pairing_t pairing, element_t msk, const char *filename) {
    size_t buffer_len;
    unsigned char *buffer = read_file_content(filename, &buffer_len);
     if (!buffer || buffer_len == 0) {
        fprintf(stderr, "Fatal: Failed to read master secret key from '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    // Use the buffer deserialization function
    if (deserialize_zr_from_buffer(pairing, msk, buffer, buffer_len) != 0) {
        free(buffer);
        fprintf(stderr, "Fatal: Failed to parse master secret key from file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    free(buffer);
}

void load_user_private_key(pairing_t pairing, element_t user_sk, const char *filename) {
    size_t buffer_len;
    unsigned char *buffer = read_file_content(filename, &buffer_len);
    if (!buffer || buffer_len == 0) {
        fprintf(stderr, "Fatal: Failed to read user private key from '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    // Use the buffer deserialization function
    if (deserialize_private_key_from_buffer(pairing, user_sk, buffer, buffer_len) != 0) {
        free(buffer);
        fprintf(stderr, "Fatal: Failed to parse user private key from file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    free(buffer);
}

void save_user_private_key(element_t user_sk, const char *filename) {
    int sk_len = element_length_in_bytes_compressed(user_sk);
    if (sk_len <= 0) {
        DIE("Failed to get compressed private key length for saving");
    }
    unsigned char *buf = (unsigned char *)malloc(sk_len);
    if (!buf) DIE("Malloc failed for user sk save buffer");

    element_to_bytes_compressed(buf, user_sk);
    write_file_content(filename, buf, sk_len); // write_file_content handles errors/exit
    free(buf);
}

void load_zr_element(pairing_t pairing, element_t zr_val, const char *filename) {
    size_t buffer_len;
    unsigned char *buffer = read_file_content(filename, &buffer_len);
    if (!buffer || buffer_len == 0) {
        fprintf(stderr, "Fatal: Failed to read Zr element from '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    if (deserialize_zr_from_buffer(pairing, zr_val, buffer, buffer_len) != 0) {
        free(buffer);
        fprintf(stderr, "Fatal: Failed to parse Zr element from file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    free(buffer);
}

void save_zr_element(element_t zr_val, const char *filename) {
    int len = element_length_in_bytes(zr_val);
    if (len <= 0) {
        DIE("Failed to get Zr element length for saving");
    }
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) DIE("Malloc failed for Zr save buffer");

    element_to_bytes(buf, zr_val);
    write_file_content(filename, buf, len);
    free(buf);
}

/* --- Hashing Implementation --- */

// Hashes an ID string into a G1 element Q. Initializes Q.
void hash_id_to_G1(element_t Q, const char *id, pairing_t pairing) {
    if (!id) {
         fprintf(stderr, "Error in hash_id_to_G1: id string is NULL.\n");
         // Handle error appropriately, maybe initialize Q to identity or exit
         element_init_G1(Q, pairing);
         element_set0(Q); // Set to identity (additive notation) / 1 (multiplicative)
         return; // Or exit
    }
    element_init_G1(Q, pairing);
    // Use the standard PBC hash function
    element_from_hash(Q, (void*)id, strlen(id));
}

// Hashes a message buffer into a Zr element h. Initializes h.
void hash_message_to_Zr(element_t h, const unsigned char *msg, size_t msg_len, pairing_t pairing) {
    element_init_Zr(h, pairing);
    // Handle NULL message buffer if msg_len is 0? Or assume valid pointer if len > 0.
    // Let's assume msg is valid if msg_len > 0. If msg_len is 0, hash of empty string.
    unsigned char hash_buf[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, hash_buf); // SHA256 handles NULL msg if msg_len is 0 correctly
    element_from_hash(h, hash_buf, SHA256_DIGEST_LENGTH);
}

/* --- Wasm Buffer Deserialization Implementations --- */

// Deserialize compressed G1 element
int deserialize_g1_compressed_from_buffer(
    pairing_t pairing,
    element_t el_g1,
    const unsigned char* buffer,
    size_t buffer_len
) {
    if (!buffer) {
        fprintf(stderr, "Deserialize G1 Error: Input buffer is NULL.\n");
        return 1; // Use non-zero for error
    }
    element_init_G1(el_g1, pairing); // Initialize the element
    int expected_len = element_length_in_bytes_compressed(el_g1);
    if (expected_len <= 0) {
         fprintf(stderr, "Deserialize G1 Error: Invalid expected compressed length (%d).\n", expected_len);
         element_clear(el_g1); // Clear element on error
         return 2;
    }
    // Allow zero-length buffer only if expected length is also zero (unlikely for G1)
    if (buffer_len == 0 && expected_len != 0) {
         fprintf(stderr, "Deserialize G1 Error: Input buffer is empty, expected %d bytes.\n", expected_len);
         element_clear(el_g1);
         return 3;
    }
     if (buffer_len != (size_t)expected_len) {
        fprintf(stderr, "Deserialize G1 Error: Buffer length mismatch (expected %d, got %zu).\n", expected_len, buffer_len);
         element_clear(el_g1);
        return 4;
    }
    // Perform the deserialization
    // Note: element_from_bytes_compressed returns bytes read or 0 on error
    if (element_from_bytes_compressed(el_g1, (unsigned char*)buffer) != expected_len) {
        fprintf(stderr, "Deserialize G1 Error: PBC element_from_bytes_compressed failed.\n");
         element_clear(el_g1);
        return 5;
    }
    return 0; // Success
}

// Deserialize Zr element
int deserialize_zr_from_buffer(
    pairing_t pairing,
    element_t el_zr,
    const unsigned char* buffer,
    size_t buffer_len
) {
     if (!buffer) {
        fprintf(stderr, "Deserialize Zr Error: Input buffer is NULL.\n");
        return 1;
    }
    element_init_Zr(el_zr, pairing); // Initialize
    int expected_len = element_length_in_bytes(el_zr);
     if (expected_len <= 0) {
         fprintf(stderr, "Deserialize Zr Error: Invalid expected length (%d).\n", expected_len);
         element_clear(el_zr);
         return 2;
     }
     if (buffer_len == 0 && expected_len != 0) {
         fprintf(stderr, "Deserialize Zr Error: Input buffer is empty, expected %d bytes.\n", expected_len);
         element_clear(el_zr);
         return 3;
     }
    if (buffer_len != (size_t)expected_len) {
        fprintf(stderr, "Deserialize Zr Error: Buffer length mismatch (expected %d, got %zu).\n", expected_len, buffer_len);
        element_clear(el_zr);
        return 4;
    }
    // Perform deserialization
    element_from_bytes(el_zr, (unsigned char*)buffer);
    // element_from_bytes returns void, cannot directly check error here.
    // Could potentially check if the element is valid if PBC provides such a function.
    return 0; // Success (assuming correct length means success)
}

// Deserialize public parameters (compressed g || compressed P_pub)
int deserialize_public_params_from_buffer(
    pairing_t pairing,
    element_t g,
    element_t P_pub,
    const unsigned char* buffer,
    size_t buffer_len
) {
    if (!buffer) {
        fprintf(stderr, "Deserialize PP Error: Input buffer is NULL.\n");
        return 1;
    }
    // Initialize elements first to get expected lengths
    element_init_G1(g, pairing);
    element_init_G1(P_pub, pairing);

    int g_len_comp = element_length_in_bytes_compressed(g);
    int p_pub_len_comp = element_length_in_bytes_compressed(P_pub);

    if (g_len_comp <= 0 || p_pub_len_comp <= 0) {
         fprintf(stderr, "Deserialize PP Error: Invalid compressed lengths for g (%d) or P_pub (%d).\n", g_len_comp, p_pub_len_comp);
         element_clear(g); element_clear(P_pub); // Clear partially initialized elements
         return 2;
    }

    size_t expected_total_len = (size_t)g_len_comp + (size_t)p_pub_len_comp;
     if (buffer_len == 0 && expected_total_len != 0) {
         fprintf(stderr, "Deserialize PP Error: Input buffer is empty, expected %zu bytes.\n", expected_total_len);
         element_clear(g); element_clear(P_pub);
         return 3;
     }
    if (buffer_len != expected_total_len) {
        fprintf(stderr, "Deserialize PP Error: Buffer length mismatch (expected %zu, got %zu).\n", expected_total_len, buffer_len);
        element_clear(g); element_clear(P_pub);
        return 4;
    }

    // Deserialize g
    if (element_from_bytes_compressed(g, (unsigned char*)buffer) != g_len_comp) {
         fprintf(stderr, "Deserialize PP Error: Failed to deserialize g.\n");
         element_clear(g); element_clear(P_pub);
         return 5;
    }
    // Deserialize P_pub (starts after g)
    if (element_from_bytes_compressed(P_pub, (unsigned char*)buffer + g_len_comp) != p_pub_len_comp) {
         fprintf(stderr, "Deserialize PP Error: Failed to deserialize P_pub.\n");
         element_clear(g); element_clear(P_pub); // Clear g as well
         return 6;
    }

    return 0; // Success
}