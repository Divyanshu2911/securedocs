#include <pbc/pbc.h>
#include "bls_ibe_util.h"
#include <stdio.h>

#define PARAM_FILE "a.param"
#define MAX_FILENAME_LEN 512

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <identity>\n", argv[0]);
        return 1;
    }
    const char *ID = argv[1];

    pairing_t pairing;
    element_t usk, usk_inv;
    element_t zero_el; // Element to represent zero

    // Initialize pairing
    initialize_pairing(pairing, PARAM_FILE);

    // Initialize elements
    element_init_Zr(usk, pairing);
    element_init_Zr(usk_inv, pairing);
    element_init_Zr(zero_el, pairing); // Initialize the zero element in Zr
    element_set0(zero_el);             // Set it explicitly to zero

    // Generate user secret usk (must be non-zero for inversion)
    do {
        element_random(usk);
        // Compare usk with the zero element.
        // element_cmp returns 0 if they are equal.
        // Continue looping if usk IS equal to zero.
    } while (element_cmp(usk, zero_el) == 0); // <-- Use element_cmp instead

    // Compute inverse: usk_inv = usk^-1 mod p
    element_invert(usk_inv, usk);

    // Save usk locally and securely
    char user_secret_file[MAX_FILENAME_LEN];
    snprintf(user_secret_file, sizeof(user_secret_file), "%s_user_secret.dat", ID);
    save_zr_element(usk, user_secret_file);

    // Save usk_inv (blinding factor) to be sent to server
    char blinding_factor_file[MAX_FILENAME_LEN];
    snprintf(blinding_factor_file, sizeof(blinding_factor_file), "%s_blinding_factor.dat", ID);
    save_zr_element(usk_inv, blinding_factor_file);

    printf("User '%s' initialization complete.\n", ID);
    printf("  User secret saved to: %s (KEEP THIS SECRET!)\n", user_secret_file);
    printf("  Blinding factor saved to: %s (Send this to the server)\n", blinding_factor_file);

    // Cleanup
    element_clear(usk);
    element_clear(usk_inv);
    element_clear(zero_el); // Clear the zero element too
    pairing_clear(pairing);

    return 0;
}