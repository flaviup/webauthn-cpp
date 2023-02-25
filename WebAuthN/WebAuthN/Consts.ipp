//
//  Consts.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_CONSTS_IPP
#define WEBAUTHN_WEBAUTHN_CONSTS_IPP

#include <chrono>

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    inline constexpr const auto ERR_FMT_FIELD_EMPTY         = "the field {} must be configured but it is empty";
    inline constexpr const auto ERR_FMT_FIELD_NOT_VALID_URI = "field {} is not a valid URI: {}";
    inline constexpr const auto ERR_FMT_CONFIG_VALIDATE     = "error occurred validating the configuration: {}";

    inline constexpr const auto DEFAULT_TIMEOUT_UVD = std::chrono::milliseconds(120'000LL);
    inline constexpr const auto DEFAULT_TIMEOUT     = std::chrono::milliseconds(300'000LL);
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_CONSTS_IPP */