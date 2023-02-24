//
//  Crypto.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/24/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_CRYPTO_IPP
#define WEBAUTHN_UTIL_CRYPTO_IPP

#include <algorithm>
#include <string>
#include <vector>
#include <sodium.h>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Crypto {

    std::vector<uint8_t> SHA256(const std::string& str) {

        unsigned char out[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(out, reinterpret_cast<const unsigned char*>(str.data()), str.size());

        return std::vector<uint8_t>(out, out + crypto_hash_sha256_BYTES);
    }
} // namespace WebAuthN::Util::Crypto

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CRYPTO_IPP */