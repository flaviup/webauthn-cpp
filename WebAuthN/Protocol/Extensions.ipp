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

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {
    using AuthenticationExtensionsClientOutputs = std::map<std::string, bool>;
    inline const std::string ExtensionAppID = "appid";
    inline const std::string ExtensionAppIDExclude = "appidExclude";
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_EXTENSIONS_IPP */
