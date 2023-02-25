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
#include "Credential.ipp"
#include "../Protocol/Assertion.ipp"

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

        // Registration

        // RegistrationOptionHandlerType describes a function which modifies the registration Protocol::PublicKeyCredentialCreationOptionsType
        // values.
        //using RegistrationOptionHandlerType = void (*)(Protocol::PublicKeyCredentialCreationOptionsType&);
        using RegistrationOptionHandlerType = std::function<void(Protocol::PublicKeyCredentialCreationOptionsType&)>;

        // BeginRegistration generates a new set of registration data to be sent to the client and authenticator.
        template<size_t N>
        Protocol::expected<std::pair<Protocol::CredentialCreationType, SessionDataType>>
        BeginRegistration(const IUser& user, const RegistrationOptionHandlerType (&opts)[N] = RegistrationOptionHandlerType[]{}) noexcept;

        // FinishRegistration takes the response from the authenticator and client and verifies the credential against the user's
        // credentials and session data.
        Protocol::expected<CredentialType>
        FinishRegistration(const IUser& user, const SessionDataType& sessionData, const std::string& response) noexcept;

        // WithAuthenticatorSelection adjusts the non-default parameters regarding the authenticator to select during
        // registration.
        inline static RegistrationOptionHandlerType WithAuthenticatorSelection(const Protocol::AuthenticatorSelectionType& authenticatorSelection) noexcept {

            return [&authenticatorSelection](Protocol::PublicKeyCredentialCreationOptionsType& cco) {


                cco.AuthenticatorSelection = authenticatorSelection;
            };
        }

        // WithExclusions adjusts the non-default parameters regarding credentials to exclude from registration.
        inline static RegistrationOptionHandlerType WithExclusions(const std::vector<Protocol::CredentialDescriptorType>& excludeList) noexcept {

            return [&excludeList](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                cco.CredentialExcludeList = excludeList;
            };
        }

        // WithConveyancePreference adjusts the non-default parameters regarding whether the authenticator should attest to the
        // credential.
        inline static RegistrationOptionHandlerType WithConveyancePreference(Protocol::ConveyancePreferenceType preference) noexcept {

            return [&preference](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                cco.Attestation = preference;
            };
        }

        // WithExtensions adjusts the extension parameter in the registration options.
        inline static RegistrationOptionHandlerType WithExtensions(const Protocol::AuthenticationExtensionsType& extensions) noexcept {

            return [&extensions](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                cco.Extensions = extensions;
            };
        }

        // WithCredentialParameters adjusts the credential parameters in the registration options.
        inline static RegistrationOptionHandlerType WithCredentialParameters(const std::vector<Protocol::CredentialParameterType>& credentialParams) noexcept {

            return [&credentialParams](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                cco.Parameters = credentialParams;
            };
        }

        // WithAppIdExcludeExtension automatically includes the specified appid if the CredentialExcludeList contains a credential
        // with the type `fido-u2f`.
        inline static RegistrationOptionHandlerType WithAppIdExcludeExtension(const std::string& appid) noexcept {

            return [&appid](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                if (!cco.CredentialExcludeList) return;

                for (const auto& credential : cco.CredentialExcludeList.value()) {

                    if (credential.AttestationType == Protocol::CREDENTIAL_TYPE_FIDO_U2F) {
                        
                        if (!cco.Extensions) {
                            cco.Extensions = Protocol::AuthenticationExtensionsType{};
                        }
                        cco.Extensions.value()[Protocol::EXTENSION_APPID_EXCLUDE] = appid;
                    }
                }
            };
        }

        // WithResidentKeyRequirement sets both the resident key and require resident key protocol options.
        inline static RegistrationOptionHandlerType WithResidentKeyRequirement(Protocol::ResidentKeyRequirementType requirement) noexcept {

            return [&requirement](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

                if (!cco.AuthenticatorSelection) {
                    cco.AuthenticatorSelection = Protocol::AuthenticatorSelectionType{};
                }
                cco.AuthenticatorSelection.value().ResidentKey = requirement;

                switch (requirement) {
                    case Protocol::ResidentKeyRequirementType::Required:
                        cco.AuthenticatorSelection.value().RequireResidentKey = Protocol::ResidentKeyRequired();
                        break;

                    default:
                        cco.AuthenticatorSelection.value().RequireResidentKey = Protocol::ResidentKeyNotRequired();
                        break;
                }
            };
        }

        // Login

        // LoginOptionHandlerType is used to provide parameters that modify the default Credential Assertion Payload that is sent to the user.
        //using LoginOptionHandlerType = void (*)(Protocol::PublicKeyCredentialRequestOptionsType&);
        using LoginOptionHandlerType = std::function<void(Protocol::PublicKeyCredentialRequestOptionsType&)>;

        // DiscoverableUserHandlerType returns a *User given the provided userHandle.
        //using DiscoverableUserHandlerType = Protocol::expected<IUser> (*)(const std::vector<uint8_t>&, const std::vector<uint8_t>&);
        using DiscoverableUserHandlerType = std::function<Protocol::expected<IUser>(const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

        // BeginLogin creates the Protocol::CredentialAssertionType data payload that should be sent to the user agent for beginning
        // the login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification. These default
        // values can be amended by providing additional LoginOption parameters. This function also returns sessionData, that
        // must be stored by the RP in a secure manner and then provided to the FinishLogin function. This data helps us verify
        // the ownership of the credential being retrieved.
        //
        // Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)
        template<size_t N>
        Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        BeginLogin(const IUser& user,
                   const LoginOptionHandlerType (&opts)[N] = LoginOptionHandlerType[]{}) noexcept;

        // BeginDiscoverableLogin begins a client-side discoverable login, previously known as Resident Key logins.
        template<size_t N>
        Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        BeginDiscoverableLogin(const LoginOptionHandlerType (&opts)[N] = LoginOptionHandlerType[]{}) noexcept;

        // FinishLogin takes the response from the client and validate it against the user credentials and stored session data.
        Protocol::expected<CredentialType>
        FinishLogin(const IUser& user, 
                    const SessionDataType& sessionData,
                    const std::string& response) noexcept;

        // ValidateLogin takes a parsed response and validates it against the user credentials and session data.
        Protocol::expected<CredentialType>
        ValidateLogin(const IUser& user, 
                      const SessionDataType& sessionData, 
                      const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept;

        // ValidateDiscoverableLogin is an overloaded version of ValidateLogin that allows for discoverable credentials.
        Protocol::expected<CredentialType>
        ValidateDiscoverableLogin(WebAuthNType::DiscoverableUserHandlerType handler, 
                                  const SessionDataType& sessionData, 
                                  const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept;

        // WithAllowedCredentials adjusts the allowed credential list with Credential Descriptors, discussed in the included
        // specification sections with user-supplied values.
        //
        // Specification: §5.10.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
        //
        // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-userverification)
        inline static LoginOptionHandlerType WithAllowedCredentials(const std::vector<Protocol::CredentialDescriptorType>& allowList) noexcept {

            return [&allowList](Protocol::PublicKeyCredentialRequestOptionsType& pkcro) {

                pkcro.AllowedCredentials = allowList;
            };
        }

        // WithUserVerification adjusts the user verification preference.
        //
        // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-userverification)
        inline static LoginOptionHandlerType WithUserVerification(const Protocol::UserVerificationRequirementType& userVerification) noexcept {

            return [&userVerification](Protocol::PublicKeyCredentialRequestOptionsType& pkcro) {

                pkcro.UserVerification = userVerification;
            };
        }

        // WithAssertionExtensions adjusts the requested extensions.
        inline static LoginOptionHandlerType WithAssertionExtensions(const Protocol::AuthenticationExtensionsType& extensions) noexcept {

            return [&extensions](Protocol::PublicKeyCredentialRequestOptionsType& pkcro) {

                pkcro.Extensions = extensions;
            };
        }

        // WithAppIdExtension automatically includes the specified appid if the AllowedCredentials contains a credential
        // with the type `fido-u2f`.
        inline static LoginOptionHandlerType WithAppIdExtension(const std::string& appid) noexcept {

            return [&appid](Protocol::PublicKeyCredentialRequestOptionsType& pkcro) {

                if (!pkcro.AllowedCredentials) return;

                for (const auto& credential : pkcro.AllowedCredentials.value()) {

                    if (credential.AttestationType == Protocol::CREDENTIAL_TYPE_FIDO_U2F) {
                        
                        if (!pkcro.Extensions) {
                            pkcro.Extensions = Protocol::AuthenticationExtensionsType{};
                        }
                        pkcro.Extensions.value()[Protocol::EXTENSION_APPID] = appid;
                    }
                }
            };
        }

    private:

        Protocol::expected<CredentialType>
        _CreateCredential(const IUser& user, 
                          const SessionDataType& sessionData, 
                          const Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept;

        template<size_t N>
        Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        _BeginLogin(const std::optional<std::vector<uint8_t>>& userID, 
                    const std::optional<std::vector<Protocol::CredentialDescriptorType>>& allowedCredentials,
                    const LoginOptionHandlerType (&opts)[N] = LoginOptionHandlerType[]{}) noexcept;
        // ValidateLogin takes a parsed response and validates it against the user credentials and session data.
        Protocol::expected<CredentialType>
        _ValidateLogin(const IUser& user, 
                       const SessionDataType& sessionData, 
                       const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept;

        ConfigType _config;
    };
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_WEBAUTHN_HPP */
