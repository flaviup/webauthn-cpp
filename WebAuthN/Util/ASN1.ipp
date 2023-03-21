//
//  ASN1.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_ASN1_IPP
#define WEBAUTHN_UTIL_ASN1_IPP

#include <string>
#include <vector>
#include <openssl/asn1.h>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::ASN1 {

    using namespace std::string_literals;

    inline expected<long> GetSequence(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SEQUENCE) {

            return unexpected("Could not parse ASN1 data as sequence"s);
        }

        return length;
    }

    inline expected<long> GetSet(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SET) {

            return unexpected("Could not parse ASN1 data as set"s);
        }

        return length;
    }

    inline long TryGetSet(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto p = data;
        auto ret = ASN1_get_object(&p, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SET) {

            return 0;
        }
        data = p;

        return length;
    }

    template<typename T = int32_t>
    inline expected<T> GetInt(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret == 0 && tagID == V_ASN1_NULL) {

            data += length;
            return static_cast<T>(0);
        }

        if (ret != 0 || length < 1 || (tagID != V_ASN1_INTEGER && tagID != V_ASN1_ENUMERATED && tagID != V_ASN1_BOOLEAN)) {

            return unexpected("Could not parse ASN1 data as int"s);
        }

        auto value = length > 7 ? MAKE_UINT64(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]) :
                                  length > 6 ? MAKE_UINT64(0, data[0], data[1], data[2], data[3], data[4], data[5], data[6]) :
                                               length > 5 ? MAKE_UINT64(0, 0, data[0], data[1], data[2], data[3], data[4], data[5]) :
                                                            length > 4 ? MAKE_UINT64(0, 0, 0, data[0], data[1], data[2], data[3], data[4]) :
                                                            length > 2 ? MAKE_UINT32(length == 4 ? data[0] : 0, length == 4 ? data[1] : data[0], length == 4 ? data[2] : data[1], length == 4 ? data[3] : data[2]) :
                                                                         length > 1 ? MAKE_UINT16(data[0], data[1]) :
                                                                                      data[0];
        data += length;

        return static_cast<T>(value);
    }

    inline expected<std::vector<uint8_t>> GetBytes(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if ((ret & 0x80) || (ret == 0xa0)) {

            return unexpected("Could not parse ASN1 data as bytes"s);
        }

        auto value = length > 0 ? std::vector<uint8_t>(data, data + length) : std::vector<uint8_t>{};
        data += length;
        
        return value;
    }

    inline expected<std::map<int, std::vector<uint8_t>>>
    GetMap(const uint8_t*& data, const size_t size) noexcept {

        std::map<int, std::vector<uint8_t>> asn1Map{};
        auto end = data + size;

        while (data < end) {

            auto length = 0L;
            auto tagID = 0, classID = 0;
            auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

            if ((ret & 0x80) || (ret == 0xa0) || tagID == V_ASN1_EOC) {

                return unexpected("Could not parse ASN1 data"s);
            }
            asn1Map[tagID] = length > 0 ? std::vector<uint8_t>(data, data + length) : std::vector<uint8_t>{};
            data += length;
        }

        return asn1Map;
    }
} // namespace WebAuthN::Util::ASN1

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_ASN1_IPP */
