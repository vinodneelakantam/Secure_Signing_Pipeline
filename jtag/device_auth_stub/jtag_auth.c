#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Platform secure firmware supplies the nonce source and signature verifier. */
extern bool secure_random_bytes(uint8_t *output, size_t output_size);
extern bool verify_debug_signature(const uint8_t *nonce, size_t nonce_size,
                                   const uint8_t *signature, size_t signature_size);
extern void soc_set_jtag_session_enabled(bool enabled);

static uint8_t pending_nonce[32];
static bool nonce_pending;

bool jtag_auth_issue_challenge(uint8_t *output, size_t output_size)
{
    if (output_size != sizeof(pending_nonce) || !secure_random_bytes(pending_nonce, sizeof(pending_nonce))) {
        return false;
    }
    nonce_pending = true;
    soc_set_jtag_session_enabled(false);
    for (size_t index = 0; index < sizeof(pending_nonce); ++index) {
        output[index] = pending_nonce[index];
    }
    return true;
}

bool jtag_auth_submit_response(const uint8_t *signature, size_t signature_size)
{
    bool accepted = nonce_pending && verify_debug_signature(pending_nonce, sizeof(pending_nonce), signature, signature_size);
    nonce_pending = false;
    soc_set_jtag_session_enabled(accepted);
    return accepted;
}