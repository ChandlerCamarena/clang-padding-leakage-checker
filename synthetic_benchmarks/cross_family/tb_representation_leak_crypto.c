// bench_cross_family_digest_boundary.c

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// --- Stub "digest" API to avoid pulling in OpenSSL in the synthetic suite.
// The point is: consumes bytes exactly as provided.
static void digest32(const void *data, size_t n, uint8_t out[32]) {
    const uint8_t *p = (const uint8_t *)data;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc ^= p[i];
    for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(acc + i);
}

// Thesis model: annotate boundary entry/exit points.
#define TRUST_BOUNDARY_IN   __attribute__((annotate("tb_in")))
#define TRUST_BOUNDARY_OUT  __attribute__((annotate("tb_out")))

typedef struct {
    uint8_t  version;     // 1 byte
    // ABI will typically insert 7 bytes padding here to align uint64_t to 8
    uint64_t nonce;       // 8 bytes
    uint32_t msg_len;     // 4 bytes
    // ABI may insert 4 bytes padding here to align next field (if any) or end struct
    uint8_t  tag[16];     // 16 bytes (pretend MAC/tag)
} HandshakeState;

// Untrusted boundary sink (e.g., IPC/RPC boundary)
TRUST_BOUNDARY_OUT void send_to_untrusted(const HandshakeState s);

// Trusted constructor
static HandshakeState build_state(uint64_t nonce, uint32_t msg_len) {
    HandshakeState s;           // automatic storage: padding indeterminate
    s.version = 1;
    s.nonce = nonce;
    s.msg_len = msg_len;

    // Cryptographic misuse: authenticating the *in-memory image*, not a canonical encoding.
    // tag becomes a function of padding bytes too.
    digest32(&s, sizeof(s), (uint8_t*)s.tag);
    return s;                   // return-by-value crosses boundary if caller is boundary-exit
}

int main(void) {
    HandshakeState st = build_state(0x1111222233334444ULL, 128);
    // Boundary transfer by value: representation (including padding) crosses trust threshold
    send_to_untrusted(st);
    return 0;
}
