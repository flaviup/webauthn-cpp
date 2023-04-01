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
#include "../Core.ipp"
#include "../Util/Base64.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    // CHALLENGE_LENGTH - Length of bytes to generate for a challenge.
    inline constexpr const size_t CHALLENGE_LENGTH = 33;

    // CreateChallenge creates a new challenge that should be signed and returned by the authenticator. The spec recommends
    // using at least 16 bytes with 100 bits of entropy. We use 33 bytes.
    inline expected<Util::URLEncodedBase64Type> CreateChallenge() noexcept {

        unsigned char challenge[CHALLENGE_LENGTH]{0};
        randombytes_buf(challenge, CHALLENGE_LENGTH);

        return Util::URLEncodedBase64_Encode(challenge, CHALLENGE_LENGTH);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CHALLENGE_IPP */
