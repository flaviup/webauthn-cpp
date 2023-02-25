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
#include <vector>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Convert {

    inline std::string ToString(const std::vector<uint8_t>& data) {

        std::string str{};
        str.reserve(data.size());
        for (int value : data) str += std::to_string(value);

        return str;
    }
} // namespace WebAuthN::Util::Convert

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CONVERT_IPP */