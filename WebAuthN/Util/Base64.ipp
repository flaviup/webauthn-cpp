//
//  Base64.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_BASE64_IPP
#define WEBAUTHN_UTIL_BASE64_IPP

#include <sodium.h>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util {

    using URLEncodedBase64Type = std::string;
    using Base64EncodedType = std::string;

#pragma GCC visibility push(hidden)

    namespace {

        static inline expected<std::string>
        _Base64_Encode(const unsigned char* str, size_t length, bool urlSafe = true) noexcept {

            const auto encodingVariant = urlSafe ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
            const auto encodedLength = sodium_base64_encoded_len(length, encodingVariant) * 2;
            char encodedString[encodedLength];
            sodium_memzero(encodedString, encodedLength);
            sodium_bin2base64(encodedString, encodedLength, str, length, encodingVariant);

            return std::string(encodedString);
        }

        static inline expected<std::vector<uint8_t>>
        _Base64_DecodeAsBinary(const std::string& encoded, bool noPadding = true, bool urlSafe = true) noexcept {

            const auto encodingVariant = noPadding ? (urlSafe ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL_NO_PADDING) :
                                                     (urlSafe ? sodium_base64_VARIANT_URLSAFE : sodium_base64_VARIANT_ORIGINAL);
            const size_t decodedMaxLength = encoded.size() * 4 / 3 + 2;
            size_t decodedLength = 0;
            unsigned char decodedData[decodedMaxLength];
            sodium_memzero(decodedData, decodedMaxLength);

            if (sodium_base642bin(decodedData, decodedMaxLength, 
                                encoded.data(), encoded.size(),
                                nullptr, &decodedLength,
                                nullptr, encodingVariant) != 0) {
                return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding"));
            }

            return std::vector<uint8_t>(decodedData, decodedData + decodedLength);
        }
    } // namespace

#pragma GCC visibility pop

    static inline expected<std::string>
    Base64_Decode(const char* encoded, const size_t size, const bool noPadding = true, const bool urlSafe = true) noexcept {

        const auto encodingVariant = noPadding ? (urlSafe ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL_NO_PADDING) :
                                                 (urlSafe ? sodium_base64_VARIANT_URLSAFE : sodium_base64_VARIANT_ORIGINAL);
        const size_t decodedMaxLength = size * 4 / 3 + 2;
        size_t decodedLength = 0;
        unsigned char decodedData[decodedMaxLength];
        sodium_memzero(decodedData, decodedMaxLength);

        if (sodium_base642bin(decodedData, decodedMaxLength, 
                              encoded, size,
                              nullptr, &decodedLength,
                              nullptr, encodingVariant) != 0) {
            return unexpected(ErrParsingData().WithInfo("base64_decode_error").WithDetails("Error base64 decoding"));
        }

        return std::string(reinterpret_cast<const char*>(decodedData));
    }

    // URLEncodedBase64Type

    inline expected<URLEncodedBase64Type> URLEncodedBase64_Encode(const unsigned char* str, size_t length) noexcept {

        return _Base64_Encode(str, length);
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

    inline expected<std::string> URLEncodedBase64_Decode(const URLEncodedBase64Type& encoded, bool noPadding = true) noexcept {

        return Base64_Decode(encoded.data(), encoded.size(), noPadding);
    }

    inline expected<std::vector<uint8_t>> URLEncodedBase64_DecodeAsBinary(const URLEncodedBase64Type& encoded, bool noPadding = true) noexcept {

        return _Base64_DecodeAsBinary(encoded, noPadding);
    }

    // Base64EncodedType

    inline expected<Base64EncodedType> Base64_Encode(const unsigned char* str, size_t length) noexcept {

        return _Base64_Encode(str, length, false);
    }

    inline expected<Base64EncodedType> Base64_Encode(const char* str) noexcept {

        return Base64_Encode(reinterpret_cast<const unsigned char*>(str), std::strlen(str));
    }

    inline expected<Base64EncodedType> Base64_Encode(const std::string& str) noexcept {

        return Base64_Encode(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

    inline expected<Base64EncodedType> Base64_Encode(const std::vector<uint8_t>& data) noexcept {

        return Base64_Encode(data.data(), data.size());
    }

    inline expected<std::string> Base64_Decode(const Base64EncodedType& encoded, bool noPadding = true) noexcept {

        return Base64_Decode(encoded.data(), encoded.size(), noPadding, false);
    }

    inline expected<std::vector<uint8_t>> Base64_DecodeAsBinary(const Base64EncodedType& encoded, bool noPadding = true) noexcept {

        return _Base64_DecodeAsBinary(encoded, noPadding, false);
    }
} // namespace WebAuthN::Util

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_BASE64_IPP */
