//
//  Time.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/24/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_TIME_IPP
#define WEBAUTHN_UTIL_TIME_IPP

#include <chrono>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Time {

    inline int64_t Timestamp() noexcept {

        const auto now = std::chrono::system_clock::now();

        // transform the time into a duration since the epoch
        const auto epoch = now.time_since_epoch();

        // cast the duration into milliseconds
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);

        // return the number of milliseconds
        return millis.count();
    }
} // namespace WebAuthN::Util::Time

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_TIME_IPP */