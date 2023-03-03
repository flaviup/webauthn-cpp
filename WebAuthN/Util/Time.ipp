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
#include <cstdio>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Time {

    using namespace std::string_literals;

    inline int64_t Timestamp() noexcept {

        const auto now = std::chrono::system_clock::now();

        // transform the time into a duration since the epoch
        const auto epoch = now.time_since_epoch();

        // cast the duration into milliseconds
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);

        // return the number of milliseconds
        return millis.count();
    }

    inline expected<int64_t> ParseISO8601(const std::string& dateTime) noexcept {

        const auto count = std::count(dateTime.cbegin(), dateTime.cend(), ':');
        int year{0}, month{0}, day{0}, hour{0}, minute{0};
        float second{0};
        int result = 0;

        if (count > 2) {

            int tzh{0}, tzm{0};
            result = sscanf(dateTime.c_str(), "%d-%d-%dT%d:%d:%f:%d:%dZ", &year, &month, &day, &hour, &minute, &second, &tzh, &tzm);

            if (result != EOF && 6 < result) {

                if (tzh < 0) {

                    tzm = -tzm;    // Fix the sign on minutes.
                }
            }
        } else {
        
            result = sscanf(dateTime.c_str(), "%d-%d-%dT%d:%d:%fZ", &year, &month, &day, &hour, &minute, &second);
        }

        if (result < 6) {

            return unexpected("Failed to parse ISO8601 date time string "s + dateTime);
        }

        std::tm t{
            .tm_year  = year - 1900,
            .tm_mon   = month - 1,
            .tm_mday  = day,
            .tm_hour  = hour,
            .tm_min   = minute,
            .tm_sec   = static_cast<int>(second),
            .tm_isdst = -1
        };
        const auto tp = std::chrono::system_clock::from_time_t(std::mktime(&t));
        const auto epoch = tp.time_since_epoch();
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);

        return millis.count() + static_cast<int>((second - t.tm_sec) * 1000);
    }
} // namespace WebAuthN::Util::Time

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_TIME_IPP */