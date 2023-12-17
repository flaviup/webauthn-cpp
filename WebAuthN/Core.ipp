//
//  Core.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_CORE_IPP
#define WEBAUTHN_CORE_IPP

#define JSON_DISABLE_ENUM_SERIALIZATION 1

#include "Errors.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN {

    template<typename T>
    struct ValueType {

        const T& Value;
    };

    using OptionalError = UtilCpp::OptionalError;
    using SuccessResult = UtilCpp::SuccessResult;
    using ErrorWrapper = UtilCpp::ErrorWrapper;
    using UtilCpp::MakeOptionalError;
    using UtilCpp::MakeResultError;
    using UtilCpp::MakeError;
    template<typename T>
    using expected = UtilCpp::expected<T>;
    inline constexpr auto NoError = UtilCpp::NoError;
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_CORE_IPP */
