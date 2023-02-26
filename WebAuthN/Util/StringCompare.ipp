//
//  StringCompare.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/25/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_STRINGCOMPARE_IPP
#define WEBAUTHN_UTIL_STRINGCOMPARE_IPP

#define UCHAR_TYPE char16_t

#include <cassert>
#include <unicode/uchar.h>
#include <unicode/ustring.h>
#include "Convert.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::StringCompare {

    inline bool Utf8EqualFold(const std::string& utf8Str1, const std::string& utf8Str2) noexcept {

        try {

            const auto us1 = Util::Convert::Utf8ToUcs2(utf8Str1);
            const auto us2 = Util::Convert::Utf8ToUcs2(utf8Str2);
            return u_strcasecmp(us1.data(), us2.data(), U_FOLD_CASE_DEFAULT) == 0;
        } catch (const std::exception& e) {
        }

        return false;
    }

    bool ConstantTimeEqual(const std::string& s1, const std::string& s2) noexcept {

        assert(s1.size() == s2.size());
        
        volatile char c = 0;
        volatile auto n = s1.size();
        volatile const char* p1 = s1.data();
        volatile const char* p2 = s2.data();

        for (volatile auto i = 0; i < n; ++i) {
            c |= p1[i] ^ p2[i];
        }

        return (c == 0);
    }
} // namespace WebAuthN::Util::StringCompare

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_STRINGCOMPARE_IPP */