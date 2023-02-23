//
//  Core.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CORE_IPP
#define WEBAUTHN_PROTOCOL_CORE_IPP

#define JSON_DISABLE_ENUM_SERIALIZATION 1

#include "Errors.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    template<typename T>
    using expected = tl::expected<T, ErrorType>;
    using unexpected = tl::unexpected<ErrorType>;
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CORE_IPP */