#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>

#include <crypto/minotaurx/minotaur.h>

extern "C" {

// Classical Minotaur, used for Hive 1.2 Bee Hash.
// Different from hardened MinotaurX.
int lcc_minotaur_hash(
    const unsigned char* data,
    size_t length,
    unsigned char* output
) {
    if (output == nullptr || data == nullptr || length == 0)
        return -1;

    try {
        const uint256 result = Minotaur(
            data,
            data + length,
            false
        );

        std::memcpy(output, result.begin(), 32);
        return 0;
    } catch (...) {
        return -1;
    }
}



// Return 0 on success and -1 on failure.
// The output is the 32-byte hash in Core's internal byte order.
int lcc_minotaurx_hash(
    const unsigned char* data,
    size_t length,
    unsigned char* output
) {
    if (output == nullptr || data == nullptr || length == 0)
        return -1;

    try {
        const uint256 result = Minotaur(
            data,
            data + length,
            true
        );

        std::memcpy(output, result.begin(), 32);
        return 0;
    } catch (...) {
        return -1;
    }
}

}
