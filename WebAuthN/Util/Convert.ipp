//
//  Convert.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_CONVERT_IPP
#define WEBAUTHN_UTIL_CONVERT_IPP

#include <string>
#include <codecvt>
#include <vector>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Convert {

    inline std::string ToString(const std::vector<uint8_t>& data) {

        std::string str{};
        str.reserve(data.size());
        for (int value : data) str += std::to_string(value);

        return str;
    }

    // Given a UTF-8 encoded string return a new UCS-2 string.
    inline std::u16string Utf8ToUcs2(const std::string& input) {

        using convert_type = std::codecvt_utf8<char16_t>;
        static std::wstring_convert<convert_type, char16_t> convert;
        
        try {
            return convert.from_bytes(input);
        } catch (const std::range_error&) {
            throw std::range_error("Failed UCS-2 conversion of message body. Check all "
                                   "characters are valid GSM-7, GSM 8-bit text, or UCS-2 "
                                   "characters"
                                   );
        }
    }
} // namespace WebAuthN::Util::Convert

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CONVERT_IPP */