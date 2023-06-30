//
//  Version.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_VERSION_IPP
#define WEBAUTHN_VERSION_IPP

#include <cstdint>

#pragma GCC visibility push(default)

#define WEBAUTHNCPP_MAJOR_VERSION 1
#define WEBAUTHNCPP_MINOR_VERSION 0
#define WEBAUTHNCPP_REVISION 0
#define WEBAUTHNCPP_VERSION_BUILD_IMPL(major, minor, revision) #major"."#minor"."#revision
#define WEBAUTHNCPP_VERSION_BUILD(major, minor, revision) WEBAUTHNCPP_VERSION_BUILD_IMPL(major, minor, revision)
#define WEBAUTHNCPP_VERSION WEBAUTHNCPP_VERSION_BUILD(WEBAUTHNCPP_MAJOR_VERSION, WEBAUTHNCPP_MINOR_VERSION, WEBAUTHNCPP_REVISION)
#define WEBAUTHNCPP_VERSION_CHECK(major, minor) ((major == WEBAUTHNCPP_MAJOR_VERSION) && (minor <= WEBAUTHNCPP_MINOR_VERSION))
#define WEBAUTHNCPP_AUTHOR "Flaviu Pasca"
#define WEBAUTHNCPP_DATE "04/02/2023"

constexpr const struct {
    const char* const string;
    const char* const author;
    const char* const date;
    const uint8_t major;
    const uint8_t minor;
    const uint8_t revision;
} WEBAUTHNCPP_Version = {
    "Version: " WEBAUTHNCPP_VERSION,
    "Author: " WEBAUTHNCPP_AUTHOR,
    "Date: " WEBAUTHNCPP_DATE,
    WEBAUTHNCPP_MAJOR_VERSION, 
    WEBAUTHNCPP_MINOR_VERSION, 
    WEBAUTHNCPP_REVISION
};

#pragma GCC visibility pop

#endif /* WEBAUTHN_VERSION_IPP */
