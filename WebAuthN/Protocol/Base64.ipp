//
//  Base64.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_BASE64_IPP
#define WEBAUTHN_PROTOCOL_BASE64_IPP

#include <string>
#include "../../cpp-base64/base64.h"
#include "Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using URLEncodedBase64Type = std::string;

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const char* str) noexcept {

        return URLEncodedBase64_Encode(std::string(str));
    }

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const std::string& str) noexcept {

        try {

            return base64_encode(str, true);
        } catch (const std::exception& e) {
            return unexpected(ErrParsingData().WithInfo("base64_encode_error").WithDetails("Error base64 encoding."));
        }
    }

    inline expected<std::string> URLEncodedBase64_Decode(const URLEncodedBase64Type& encoded) noexcept {

        try {

            return base64_decode(encoded, true);
        } catch (const std::exception& e) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding."));
        }
    }

} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_BASE64_IPP */
