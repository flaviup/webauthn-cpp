//
//  UrlParse.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_URL_PARSE_IPP
#define WEBAUTHN_UTIL_URL_PARSE_IPP

#include <algorithm>
#include <string>
#include <regex>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Url {

#pragma GCC visibility push(hidden)

    namespace {
        static inline constexpr const auto SCHEME_REGEX   = "((http[s]?)://)?";  // match http or https before the ://
        static inline constexpr const auto USER_REGEX     = "(([^@/:\\s]+)@)?";  // match anything other than @ / : or whitespace before the ending @
        static inline constexpr const auto HOST_REGEX     = "([^@/:\\s]+)";      // mandatory. match anything other than @ / : or whitespace
        static inline constexpr const auto PORT_REGEX     = "(:([0-9]{1,5}))?";  // after the : match 1 to 5 digits
        static inline constexpr const auto PATH_REGEX     = "(/[^:#?\\s]*)?";    // after the / match anything other than : # ? or whitespace
        static inline constexpr const auto QUERY_REGEX    = "(\\?(([^?;&#=]+=[^?;&#=]+)([;|&]([^?;&#=]+=[^?;&#=]+))*))?"; // after the ? match any number of x=y pairs, seperated by & or ;
        static inline constexpr const auto FRAGMENT_REGEX = "(#([^#\\s]*))?";    // after the # match anything other than # or whitespace

        static inline const std::regex URL_REGEX{std::string("^")
                                               + SCHEME_REGEX + USER_REGEX
                                               + HOST_REGEX + PORT_REGEX
                                               + PATH_REGEX + QUERY_REGEX
                                               + FRAGMENT_REGEX + "$"};
    }

#pragma GCC visibility pop

    inline bool Parse(const std::string& url) {

        std::smatch matchResults;
        return std::regex_match(url.cbegin(), url.cend(), matchResults, URL_REGEX);
    }

    // FullyQualifiedOrigin returns the origin per the HTML spec: (scheme)://(host)[:(port)].
    inline bool FullyQualifiedOrigin(const std::string& rawOrigin, std::string& fqo) noexcept {

        const std::string androidPrefix = "android:apk-key-hash:";

        if (rawOrigin.size() >= androidPrefix.size()) {

            auto res = std::mismatch(androidPrefix.cbegin(), androidPrefix.cend(), rawOrigin.cbegin());

            if (res.first == androidPrefix.cend()) { // androidPrefix is a prefix of rawOrigin

                fqo = androidPrefix;
                return true;
            }
        }
        std::smatch matchResults;

        if (std::regex_match(rawOrigin.cbegin(), rawOrigin.cend(), matchResults, URL_REGEX)) {

            std::string scheme;
            //std::string user;
            std::string host;
            std::string port;
            //std::string path;
            //std::string query;
            //std::string fragment;
            scheme.assign(matchResults[2].first, matchResults[2].second);
            //user.assign(matchResults[4].first, matchResults[4].second);
            host.assign(matchResults[5].first, matchResults[5].second);
            port.assign(matchResults[7].first, matchResults[7].second);
            //path.assign(matchResults[8].first, matchResults[8].second);
            //query.assign(matchResults[10].first, matchResults[10].second);
            //fragment.assign(matchResults[15].first, matchResults[15].second);

            if (!host.empty()) {

                fqo = (scheme.empty() ? host : scheme + "://" + host) + (port.empty() ? "" : ":" + port);
                return true;
            }
        }
        fqo = "";

        return false;
    }
} // namespace WebAuthN::Util::Url

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_URL_PARSE_IPP */