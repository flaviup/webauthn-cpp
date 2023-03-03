//
//  Base64.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_BASE64_IPP
#define WEBAUTHN_PROTOCOL_BASE64_IPP

#include <sodium.h>
//#include "../../cpp-base64/base64.h"
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using URLEncodedBase64Type = std::string;

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const unsigned char* str, size_t length) noexcept {

        /*try {

            return base64_encode(str, length, true);
        } catch (const std::exception&) {
            return unexpected(ErrParsingData().WithInfo("base64_encode_error").WithDetails("Error base64 encoding."));
        }*/

        constexpr auto encodingVariant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        const auto encodedLength = sodium_base64_encoded_len(length, encodingVariant) * 2;
        char encodedString[encodedLength];
        sodium_memzero(encodedString, encodedLength);
        sodium_bin2base64(encodedString, encodedLength, str, length, encodingVariant);
        
        return std::string(encodedString);
    }

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const char* str) noexcept {

        return URLEncodedBase64_Encode(reinterpret_cast<const unsigned char*>(str), std::strlen(str));
    }

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const std::string& str) noexcept {

        return URLEncodedBase64_Encode(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const std::vector<uint8_t>& data) noexcept {

        return URLEncodedBase64_Encode(data.data(), data.size());
    }

    inline expected<std::string> URLEncodedBase64_Decode(const URLEncodedBase64Type& encoded) noexcept {

        /*try {

            return base64_decode(encoded, true);
        } catch (const std::exception&) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding."));
        }*/

        constexpr auto encodingVariant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        const size_t decodedMaxLength = encoded.size() * 4 / 3 + 2;
        size_t decodedLength = 0;
        unsigned char decodedData[decodedMaxLength];
        sodium_memzero(decodedData, decodedMaxLength);

        if (sodium_base642bin(decodedData, decodedMaxLength, 
                              encoded.data(), encoded.size(),
                              nullptr, &decodedLength,
                              nullptr, encodingVariant) != 0) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding."));
        }

        return std::string(reinterpret_cast<const char*>(decodedData));
    }

    inline expected<std::vector<uint8_t>> URLEncodedBase64_DecodeAsBinary(const URLEncodedBase64Type& encoded) noexcept {

        /*try {

            auto decodedStr = base64_decode(encoded, true);
            return std::vector<uint8_t>(decodedStr.cbegin(), decodedStr.cend());
        } catch (const std::exception&) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding."));
        }*/

        constexpr auto encodingVariant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        const size_t decodedMaxLength = encoded.size() * 4 / 3 + 2;
        size_t decodedLength = 0;
        unsigned char decodedData[decodedMaxLength];
        sodium_memzero(decodedData, decodedMaxLength);

        if (sodium_base642bin(decodedData, decodedMaxLength, 
                              encoded.data(), encoded.size(),
                              nullptr, &decodedLength,
                              nullptr, encodingVariant) != 0) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding."));
        }

        return std::vector<uint8_t>(decodedData, decodedData + decodedLength);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_BASE64_IPP */
