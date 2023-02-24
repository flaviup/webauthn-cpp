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

    inline std::optional<ErrorType> URLEncodedBase64_Encode(const unsigned char* str, size_t length, URLEncodedBase64Type& encoded) noexcept {

        try {

            encoded = base64_encode(str, length, true);
        } catch (const std::exception& e) {
            return ErrParsingData().WithInfo("base64_encode_error").WithDetails("Error base64 encoding.");
        }

        return std::nullopt;
    }

    inline std::optional<ErrorType> URLEncodedBase64_Encode(const char* str, URLEncodedBase64Type& encoded) noexcept {

        return URLEncodedBase64_Encode(reinterpret_cast<const unsigned char*>(str), std::strlen(str), encoded);
    }

    inline std::optional<ErrorType> URLEncodedBase64_Encode(const std::string& str, URLEncodedBase64Type& encoded) noexcept {

        return URLEncodedBase64_Encode(reinterpret_cast<const unsigned char*>(str.data()), str.size(), encoded);
    }

    inline std::optional<ErrorType> URLEncodedBase64_Encode(const std::vector<uint8_t>& data, URLEncodedBase64Type& encoded) noexcept {

        return URLEncodedBase64_Encode(data.data(), data.size(), encoded);
    }

    inline std::optional<ErrorType> URLEncodedBase64_Decode(const URLEncodedBase64Type& encoded, std::string& decoded) noexcept {

        try {

            decoded = base64_decode(encoded, true);
        } catch (const std::exception& e) {
            return ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding.");
        }

        return std::nullopt;
    }

    inline std::optional<ErrorType> URLEncodedBase64_Decode(const URLEncodedBase64Type& encoded, std::vector<uint8_t>& decoded) noexcept {

        try {

            auto decodedStr = base64_decode(encoded, true);
            decoded = std::vector<uint8_t>(decoded.begin(), decoded.end());
        } catch (const std::exception& e) {
            return ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding.");
        }

        return std::nullopt;
    }

} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_BASE64_IPP */
