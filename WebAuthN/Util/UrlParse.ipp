//
//  UrlParse.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_URL_PARSE_IPP
#define WEBAUTHN_UTIL_URL_PARSE_IPP

#include <string>
#include <regex>

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Url {

#pragma GCC visibility push(hidden)
    
    namespace {
        inline constexpr const auto SCHEME_REGEX   = "((http[s]?)://)?";  // match http or https before the ://
        inline constexpr const auto USER_REGEX     = "(([^@/:\\s]+)@)?";  // match anything other than @ / : or whitespace before the ending @
        inline constexpr const auto HOST_REGEX     = "([^@/:\\s]+)";      // mandatory. match anything other than @ / : or whitespace
        inline constexpr const auto PORT_REGEX     = "(:([0-9]{1,5}))?";  // after the : match 1 to 5 digits
        inline constexpr const auto PATH_REGEX     = "(/[^:#?\\s]*)?";    // after the / match anything other than : # ? or whitespace
        inline constexpr const auto QUERY_REGEX    = "(\\?(([^?;&#=]+=[^?;&#=]+)([;|&]([^?;&#=]+=[^?;&#=]+))*))?"; // after the ? match any number of x=y pairs, seperated by & or ;
        inline constexpr const auto FRAGMENT_REGEX = "(#([^#\\s]*))?";    // after the # match anything other than # or whitespace

        inline const std::regex URL_REGEX{std::string("^")
                                        + SCHEME_REGEX + USER_REGEX
                                        + HOST_REGEX + PORT_REGEX
                                        + PATH_REGEX + QUERY_REGEX
                                        + FRAGMENT_REGEX + "$"};
    }

#pragma GCC visibility pop

    inline bool Parse(const std::string& url) {

        std::smatch matchResults;
        return std::regex_match(url.cbegin(), url.cend(), matchResults, URL_REGEX);
        
        /*if (std::regex_match(url.cbegin(), url.cend(), matchResults, URL_REGEX))
        {
            m_scheme.assign(matchResults[2].first, matchResults[2].second);
            m_user.assign(matchResults[4].first, matchResults[4].second);
            m_host.assign(matchResults[5].first, matchResults[5].second);
            m_port.assign(matchResults[7].first, matchResults[7].second);
            m_path.assign(matchResults[8].first, matchResults[8].second);
            m_query.assign(matchResults[10].first, matchResults[10].second);
            m_fragment.assign(matchResults[15].first, matchResults[15].second);

            return true;
        }

        return false;*/
    }
} // namespace WebAuthN::Util

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_URL_PARSE_IPP */