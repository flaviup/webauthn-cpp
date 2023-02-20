//
//  Extensions.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_EXTENSIONS_IPP
#define WEBAUTHN_PROTOCOL_EXTENSIONS_IPP

#include <any>
#include <string>
#include <map>

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {
    // Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).

    // For a list of commonly supported extensions, see §10. Defined Extensions
    // (https://www.w3.org/TR/webauthn/#sctn-defined-extensions).
    using AuthenticationExtensionsClientOutputsType = std::map<std::string, std::any>;
    inline const std::string EXTENSION_APPID = "appid";
    inline const std::string EXTENSION_APPID_EXCLUDE = "appidExclude";
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_EXTENSIONS_IPP */
