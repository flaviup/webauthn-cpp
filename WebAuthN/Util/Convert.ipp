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

    inline void ToString(const std::vector<uint8_t>& data, std::string& str) {

        std::string s{};
        s.reserve(data.size());
        for (int value : data) s += std::to_string(value);

        str = s;
    }
} // namespace WebAuthN::Util::Convert

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CONVERT_IPP */