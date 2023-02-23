//
//  WebAuthN.hpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_WEBAUTHN_HPP
#define WEBAUTHN_WEBAUTHN_WEBAUTHN_HPP

#include <functional>
#include "IUser.ipp"
#include "Config.ipp"
#include "SessionData.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    // WebAuthNType is the primary interface and contains the request handlers that should be called.
    class WebAuthNType final {

    private:
        
        WebAuthNType() noexcept = default;
        WebAuthNType(const ConfigType& config) noexcept : _config(config) {};
        WebAuthNType(const WebAuthNType&) noexcept = default;
        WebAuthNType& operator =(const WebAuthNType&) noexcept = default;

    public:

        WebAuthNType(WebAuthNType&&) noexcept = default;
        ~WebAuthNType() noexcept = default;

        WebAuthNType& operator =(WebAuthNType&&) noexcept = default;

         // New creates a new WebAuthNType object given the proper config.
        static inline Protocol::expected<WebAuthNType> New(const ConfigType& config) noexcept {

            auto validationResult = config.Validate();

            if (validationResult) {

                return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
            }

            return WebAuthNType(config);
        }

        inline const ConfigType& GetConfig() const noexcept {

            return _config;
        }

        // RegistrationOptionHandlerType describes a function which modifies the registration Protocol::PublicKeyCredentialCreationOptionsType
        // values.
        //using RegistrationOptionHandlerType = void (*)(Protocol::PublicKeyCredentialCreationOptionsType&);
        using RegistrationOptionHandlerType = std::function<void(Protocol::PublicKeyCredentialCreationOptionsType&)>;

        // Registration

        // BeginRegistration generates a new set of registration data to be sent to the client and authenticator.
        Protocol::expected<std::pair<Protocol::CredentialCreationType, SessionDataType>>
        BeginRegistration(const IUser& user, int optsCount, RegistrationOptionHandlerType opts...) noexcept;

        // FinishRegistration takes the response from the authenticator and client and verifies the credential against the user's
        // credentials and session data.
        Protocol::expected<CredentialType>
        FinishRegistration(const IUser& user, const SessionDataType& sessionData, const std::string& response) noexcept;

    private:

        Protocol::expected<CredentialType>
        _CreateCredential(const IUser& user, const SessionDataType& sessionData, Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept;

        ConfigType _config;
    };
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_WEBAUTHN_HPP */
