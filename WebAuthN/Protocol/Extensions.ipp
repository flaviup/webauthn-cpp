//
//  Extensions.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_EXTENSIONS_IPP
#define WEBAUTHN_PROTOCOL_EXTENSIONS_IPP

#include <string>
#include <map>
#include <nlohmann/json.hpp>

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).

    // For a list of commonly supported extensions, see §10. Defined Extensions
    // (https://www.w3.org/TR/webauthn/#sctn-defined-extensions).
    using AuthenticationExtensionsClientOutputsType = json::object_t;

    // AuthenticationExtensionsType represents the AuthenticationExtensionsClientInputsType IDL. This member contains additional
    // parameters requesting additional processing by the client and authenticator.
    //
    // Specification: §5.7.1. Authentication Extensions Client Inputs (https://www.w3.org/TR/webauthn/#iface-authentication-extensions-client-inputs)
    using AuthenticationExtensionsType = json::object_t;

    inline const std::string EXTENSION_APPID = "appid";
    inline const std::string EXTENSION_APPID_EXCLUDE = "appidExclude";
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_EXTENSIONS_IPP */
