//
//  Challenge.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CHALLENGE_IPP
#define WEBAUTHN_PROTOCOL_CHALLENGE_IPP

#include <cstddef>
#include <string>
#include <sodium.h>
#include "Base64.ipp"
#include "Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    // CHALLENGE_LENGTH - Length of bytes to generate for a challenge.
    inline constexpr const size_t CHALLENGE_LENGTH = 32;

    // CreateChallenge creates a new challenge that should be signed and returned by the authenticator. The spec recommends
    // using at least 16 bytes with 100 bits of entropy. We use 32 bytes.
    inline std::optional<ErrorType> CreateChallenge(URLEncodedBase64Type& encodedChallenge) noexcept {
        
        unsigned char challenge[CHALLENGE_LENGTH]{0};
        randombytes_buf(challenge, CHALLENGE_LENGTH);

        return URLEncodedBase64_Encode(challenge, CHALLENGE_LENGTH, encodedChallenge);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CHALLENGE_IPP */
