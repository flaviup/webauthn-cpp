//
//  Base64.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_BASE64_IPP
#define WEBAUTHN_PROTOCOL_BASE64_IPP

#include <cstdint>
#include <string>
#include "../../cpp-base64/base64.h"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using URLEncodedBase64 = std::string;

    inline URLEncodedBase64 JsonToURLEncodedBase64(const std::string& json) {
        return base64_encode(json, true);
    }

    inline std::string URLEncodedBase64ToJson(const URLEncodedBase64& encoded) {
        return base64_decode(encoded);
    }

} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_BASE64_IPP */
