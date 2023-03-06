//
//  WebAuthN.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_WEBAUTHN_IPP
#define WEBAUTHN_WEBAUTHN_WEBAUTHN_IPP

#include <functional>
#include "IUser.ipp"
#include "Config.ipp"
#include "SessionData.ipp"
#include "Credential.ipp"
#include "../Protocol/Assertion.ipp"
#include "../Protocol/Challenge.ipp"
#include "../Protocol/Options.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"
#include "../Util/Time.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    // WebAuthNType is the primary interface and contains the request handlers that should be called.
    class WebAuthNType final {

    private:
        
        WebAuthNType() noexcept = default;
        
        WebAuthNType(const ConfigType& config) noexcept : _config(config) {
        }

        WebAuthNType(const WebAuthNType&) noexcept = default;
        WebAuthNType& operator =(const WebAuthNType&) noexcept = default;

    public:

        WebAuthNType(WebAuthNType&&) noexcept = default;
        ~WebAuthNType() noexcept = default;

        WebAuthNType& operator =(WebAuthNType&&) noexcept = default;

         // New creates a new WebAuthNType object given the proper config.
        static inline expected<WebAuthNType> New(const ConfigType& config) noexcept {

            auto err = config.Validate();

            if (err) {

                return unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, std::string(err.value())));
            }
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
            OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS | 
                                OPENSSL_INIT_ADD_ALL_CIPHERS |
                                OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                                OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                                OPENSSL_INIT_ENGINE_OPENSSL |
                                OPENSSL_INIT_ENGINE_AFALG, nullptr);
            auto sodiumInit = sodium_init();

            if (sodiumInit != 0) {

                return unexpected(fmt::format("Could not initialize sodium: error {}.", sodiumInit));
            }

            return WebAuthNType(config);
        }

        inline const ConfigType& GetConfig() const noexcept {

            return _config;
        }

        // REGISTRATION
        // These objects help us create the CredentialCreationOptionsType
        // that will be passed to the authenticator via the user client.

        // RegistrationOptionHandlerType describes a function which modifies the registration Protocol::PublicKeyCredentialCreationOptionsType
        // values.
        //using RegistrationOptionHandlerType = void (*)(Protocol::PublicKeyCredentialCreationOptionsType&);
        using RegistrationOptionHandlerType = std::function<void(Protocol::PublicKeyCredentialCreationOptionsType&)>;

        inline static RegistrationOptionHandlerType WithDefaultRegistrationOptions() noexcept {

            return [](Protocol::PublicKeyCredentialCreationOptionsType& cco) {
            };
        }

        inline static const RegistrationOptionHandlerType DEFAULT_REGISTRATION_OPTIONS[]{
            WithDefaultRegistrationOptions()
        };

        // BeginRegistration generates a new set of registration data to be sent to the client and authenticator.
        template<size_t N>
        expected<std::pair<Protocol::CredentialCreationType, SessionDataType>>
        BeginRegistration(const IUser& user, const RegistrationOptionHandlerType (&opts)[N] = DEFAULT_REGISTRATION_OPTIONS) noexcept {

            auto err = _config.Validate();

            if (err) {

                return unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, std::string(err.value())));
            }

            auto challengeCreationResult = Protocol::CreateChallenge();

            if (!challengeCreationResult) {
                return unexpected(challengeCreationResult.error());
            }
            Protocol::URLEncodedBase64Type challenge = challengeCreationResult.value();

            Protocol::URLEncodedBase64Type entityUserID{};

            if (_config.EncodeUserIDAsString) {

                entityUserID = std::string(reinterpret_cast<const char*>(user.GetWebAuthNID().data()));
            } else {

                auto idEncodingResult = Protocol::URLEncodedBase64_Encode(user.GetWebAuthNID());

                if (!idEncodingResult) {
                    return unexpected(idEncodingResult.error());
                }
                entityUserID = idEncodingResult.value();
            }

            auto entityUser = Protocol::UserEntityType{
                entityUserID,
                user.GetWebAuthNName(),
                user.GetWebAuthNDisplayName(),
                user.GetWebAuthNIcon()
            };

            auto entityRelyingParty = Protocol::RelyingPartyEntityType{
                _config.RPID,
                _config.RPDisplayName,
                _config.RPIcon
            };

            std::vector<Protocol::CredentialParameterType> credentialParams = _GetDefaultRegistrationCredentialParameters();

            auto creation = Protocol::CredentialCreationType{
                Protocol::PublicKeyCredentialCreationOptionsType{
                    entityRelyingParty,
                    entityUser,
                    challenge,
                    credentialParams,
                    std::nullopt,
                    std::nullopt,
                    _config.AuthenticatorSelection,
                    _config.AttestationPreference
                }
            };

            for (int i = 0; i < N; ++i) {
                opts[i](creation.Response);
            }

            if (!creation.Response.Timeout || creation.Response.Timeout.value() == 0) {

                switch (creation.Response.AuthenticatorSelection.value().UserVerification.value()) {

                    case Protocol::UserVerificationRequirementType::Discouraged:
                        creation.Response.Timeout = _config.Timeouts.Registration.Timeout.count();
                        break;

                    default:
                        creation.Response.Timeout = _config.Timeouts.Registration.Timeout.count();
                        break;
                }
            }

            auto session = SessionDataType{
                challenge,
                user.GetWebAuthNID(),
                user.GetWebAuthNName(),
                user.GetWebAuthNDisplayName(),
                _config.Timeouts.Registration.Enforce ? Util::Time::Timestamp() + creation.Response.Timeout.value() : 0,
                creation.Response.AuthenticatorSelection.value().UserVerification.value()
            };

            return std::make_pair(creation, session);
        }

        // FinishRegistration takes the response from the authenticator and client and verifies the credential against the user's
        // credentials and session data.
        expected<CredentialType>
        FinishRegistration(const IUser& user, const SessionDataType& sessionData, const std::string& response) noexcept {
            
            auto parsedResponse = Protocol::ParseCredentialCreationResponse(response);

            if (!parsedResponse) {

                return unexpected(parsedResponse.error());
            }

            return _CreateCredential(user, sessionData, parsedResponse.value());
        }

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
        inline static RegistrationOptionHandlerType WithConveyancePreference(const Protocol::ConveyancePreferenceType preference) noexcept {

            return [preference](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

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
        inline static RegistrationOptionHandlerType WithResidentKeyRequirement(const Protocol::ResidentKeyRequirementType requirement) noexcept {

            return [requirement](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

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

        // LOGIN

        // These objects help us create the PublicKeyCredentialRequestOptionsType
        // that will be passed to the authenticator via the user client.

        // LoginOptionHandlerType is used to provide parameters that modify the default Credential Assertion Payload that is sent to the user.
        //using LoginOptionHandlerType = void (*)(Protocol::PublicKeyCredentialRequestOptionsType&);
        using LoginOptionHandlerType = std::function<void(Protocol::PublicKeyCredentialRequestOptionsType&)>;

        inline static LoginOptionHandlerType WithDefaultLoginOptions() noexcept {

            return [](Protocol::PublicKeyCredentialRequestOptionsType& cco) {
            };
        }

        inline static const LoginOptionHandlerType DEFAULT_LOGIN_OPTIONS[]{
            WithDefaultLoginOptions()
        };

        // DiscoverableUserHandlerType returns a *User given the provided userHandle.
        //using DiscoverableUserHandlerType = Protocol::expected<IUser> (*)(const std::vector<uint8_t>&, const std::vector<uint8_t>&);
        using DiscoverableUserHandlerType = std::function<expected<IUser*>(const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

        // BeginLogin creates the Protocol::CredentialAssertionType data payload that should be sent to the user agent for beginning
        // the login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification. These default
        // values can be amended by providing additional LoginOption parameters. This function also returns sessionData, that
        // must be stored by the RP in a secure manner and then provided to the FinishLogin function. This data helps us verify
        // the ownership of the credential being retrieved.
        //
        // Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)
        template<size_t N>
        expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        BeginLogin(const IUser& user,
                   const LoginOptionHandlerType (&opts)[N] = DEFAULT_LOGIN_OPTIONS) noexcept {

            auto credentials = user.GetWebAuthNCredentials();

            if (credentials.empty()) { // If the user does not have any credentials, we cannot perform an assertion.

                return unexpected(ErrBadRequest().WithDetails("Found no credentials for user"));
            }

            std::vector<Protocol::CredentialDescriptorType> allowedCredentials(credentials.size());
            size_t n = 0;

            for (const auto& credential : credentials) {
                allowedCredentials[n++] = credential.ToDescriptorType();
            }

            return _BeginLogin(user.GetWebAuthNID(), user.GetWebAuthNName(), user.GetWebAuthNDisplayName(), allowedCredentials, opts);
        }

        // BeginDiscoverableLogin begins a client-side discoverable login, previously known as Resident Key logins.
        template<size_t N>
        expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        BeginDiscoverableLogin(const LoginOptionHandlerType (&opts)[N] = DEFAULT_LOGIN_OPTIONS) noexcept {

            return _BeginLogin(std::nullopt, std::nullopt, std::nullopt, std::nullopt, opts);
        }

        // FinishLogin takes the response from the client and validate it against the user credentials and stored session data.
        expected<CredentialType>
        FinishLogin(const IUser& user, 
                    const SessionDataType& sessionData,
                    const std::string& response) noexcept {
            auto parsedResponse = Protocol::ParseCredentialRequestResponse(response);   

            if (!parsedResponse) {

                return unexpected(parsedResponse.error());
            }

            return ValidateLogin(user, sessionData, parsedResponse.value());
        }

        // ValidateLogin takes a parsed response and validates it against the user credentials and session data.
        expected<CredentialType>
        ValidateLogin(const IUser& user, 
                      const SessionDataType& sessionData, 
                      const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
        
            if (user.GetWebAuthNID() != sessionData.UserID) {

                return unexpected(ErrBadRequest().WithDetails("ID mismatch for User and Session"));
            }

            if (sessionData.Expires != 0LL && sessionData.Expires <= Util::Time::Timestamp()) {

                return unexpected(ErrBadRequest().WithDetails("Session has Expired"));
            }

            return _ValidateLogin(user, sessionData, parsedResponse);
        }

        // ValidateDiscoverableLogin is an overloaded version of ValidateLogin that allows for discoverable credentials.
        expected<CredentialType>
        ValidateDiscoverableLogin(const WebAuthNType::DiscoverableUserHandlerType handler, 
                                  const SessionDataType& sessionData, 
                                  const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {

            if (sessionData.UserID && !sessionData.UserID.value().empty()) {

                return unexpected(ErrBadRequest().WithDetails("Session was not initiated as a client-side discoverable login"));
            }

            if (parsedResponse.Response.UserHandle.empty()) {

                return unexpected(ErrBadRequest().WithDetails("Client-side Discoverable Assertion was attempted with a blank User Handle"));
            }

            auto handlerResult = handler(parsedResponse.RawID, parsedResponse.Response.UserHandle);

            if (!handlerResult || handlerResult.value() == nullptr) {

                return unexpected(ErrBadRequest().WithDetails("Failed to lookup Client-side Discoverable Credential"));
            }

            return _ValidateLogin(*handlerResult.value(), sessionData, parsedResponse);
        }

        // WithAllowedCredentials adjusts the allowed credential list with Credential Descriptors, discussed in the included
        // specification sections with user-supplied values.
        //
        // Specification: §5.10.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
        //
        // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-userverification)
        inline static LoginOptionHandlerType WithAllowedCredentials(const std::vector<Protocol::CredentialDescriptorType>& allowList) noexcept {

            return [&allowList](Protocol::PublicKeyCredentialRequestOptionsType& cro) {

                cro.AllowedCredentials = allowList;
            };
        }

        // WithUserVerification adjusts the user verification preference.
        //
        // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-userverification)
        inline static LoginOptionHandlerType WithUserVerification(const Protocol::UserVerificationRequirementType userVerification) noexcept {

            return [userVerification](Protocol::PublicKeyCredentialRequestOptionsType& cro) {

                cro.UserVerification = userVerification;
            };
        }

        // WithAssertionExtensions adjusts the requested extensions.
        inline static LoginOptionHandlerType WithAssertionExtensions(const Protocol::AuthenticationExtensionsType& extensions) noexcept {

            return [&extensions](Protocol::PublicKeyCredentialRequestOptionsType& cro) {

                cro.Extensions = extensions;
            };
        }

        // WithAppIdExtension automatically includes the specified appid if the AllowedCredentials contains a credential
        // with the type `fido-u2f`.
        inline static LoginOptionHandlerType WithAppIdExtension(const std::string& appid) noexcept {

            return [&appid](Protocol::PublicKeyCredentialRequestOptionsType& cro) {

                if (!cro.AllowedCredentials) return;

                for (const auto& credential : cro.AllowedCredentials.value()) {

                    if (credential.AttestationType == Protocol::CREDENTIAL_TYPE_FIDO_U2F) {
                        
                        if (!cro.Extensions) {
                            cro.Extensions = Protocol::AuthenticationExtensionsType{};
                        }
                        cro.Extensions.value()[Protocol::EXTENSION_APPID] = appid;
                    }
                }
            };
        }

    private:

        inline static std::vector<Protocol::CredentialParameterType> _GetDefaultRegistrationCredentialParameters() noexcept {
            
            namespace WebAuthNCOSE = Protocol::WebAuthNCOSE;

            return std::vector<Protocol::CredentialParameterType>{
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES384
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES512
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS256
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS384
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS512
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS256
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS384
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS512
                },
                {
                    Protocol::CredentialTypeType::PublicKey,
                    WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgEdDSA
                }
            };
        }

        // CreateCredential verifies a parsed response against the user's credentials and session data.
        expected<CredentialType>
        _CreateCredential(const IUser& user,
                          const SessionDataType& sessionData,
                          const Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept {
            
            if (user.GetWebAuthNID() != sessionData.UserID) {

                return unexpected(ErrBadRequest().WithDetails("ID mismatch for User and Session"));
            }

            if (sessionData.Expires != 0LL && sessionData.Expires <= Util::Time::Timestamp()) {

                return unexpected(ErrBadRequest().WithDetails("Session has Expired"));
            }

            auto shouldVerifyUser = (sessionData.UserVerification == Protocol::UserVerificationRequirementType::Required);
            auto verificationResultError = parsedResponse.Verify(sessionData.Challenge, shouldVerifyUser, _config.RPID, _config.RPOrigins);

            if (verificationResultError) {

                return unexpected(verificationResultError.value());
            }

            return CredentialType::Create(parsedResponse);
        }

        template<size_t N>
        expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
        _BeginLogin(const std::optional<std::vector<uint8_t>>& userID, 
                    const std::optional<std::string>& userName, 
                    const std::optional<std::string>& userDisplayName, 
                    const std::optional<std::vector<Protocol::CredentialDescriptorType>>& allowedCredentials,
                    const LoginOptionHandlerType (&opts)[N] = DEFAULT_LOGIN_OPTIONS) noexcept {
    
            auto validationResult = _config.Validate();

            if (validationResult) {

                return unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, std::string(validationResult.value())));
            }

            auto challengeCreationResult = Protocol::CreateChallenge();

            if (!challengeCreationResult) {

                return unexpected(challengeCreationResult.error());
            }
            auto challenge = challengeCreationResult.value();
            auto assertion = Protocol::CredentialAssertionType{
                Protocol::PublicKeyCredentialRequestOptionsType{
                    challenge,
                    std::nullopt,
                    _config.RPID,
                    allowedCredentials,
                    _config.AuthenticatorSelection.UserVerification
                }
            };

            for (int i = 0; i < N; ++i) {
                opts[i](assertion.Response);
            }

            if (!assertion.Response.Timeout || assertion.Response.Timeout.value() == 0) {

                switch (assertion.Response.UserVerification.value()) {

                    case Protocol::UserVerificationRequirementType::Discouraged:
                        assertion.Response.Timeout = _config.Timeouts.Login.TimeoutUVD.count();
                        break;

                    default:
                        assertion.Response.Timeout = _config.Timeouts.Login.Timeout.count();
                        break;
                }
            }

            auto session = SessionDataType{
                challenge,
                userID,
                userName,
                userDisplayName,
                _config.Timeouts.Login.Enforce ? Util::Time::Timestamp() + assertion.Response.Timeout.value() : 0,
                assertion.Response.UserVerification.value(),
                assertion.Response.GetAllowedCredentialIDs(),
                assertion.Response.Extensions
            };

            return std::make_pair(assertion, session);
        }

        // ValidateLogin takes a parsed response and validates it against the user credentials and session data.
        expected<CredentialType>
        _ValidateLogin(const IUser& user, 
                       const SessionDataType& sessionData, 
                       const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
            
            // Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
            // verify that credential.id identifies one of the public key credentials that were listed in
            // allowCredentials.

            // NON-NORMATIVE Prior Step: Verify that the allowCredentials for the session are owned by the user provided.
            auto userCredentials = user.GetWebAuthNCredentials();
            auto credentialFound = false;
            auto parsedResponseRawID = parsedResponse.RawID;

            if (sessionData.AllowedCredentialIDs && !sessionData.AllowedCredentialIDs.value().empty()) {

                for (const auto& allowedCredentialID : sessionData.AllowedCredentialIDs.value()) {

                    auto credentialsOwned = std::any_of(userCredentials.cbegin(), 
                                                        userCredentials.cend(), 
                                                        [&allowedCredentialID](const CredentialType& userCredential) { return userCredential.ID == allowedCredentialID; });

                    if (!credentialsOwned) {

                        return unexpected(ErrBadRequest().WithDetails("User does not own all credentials from the allowedCredentialList"));
                    }
                }

                credentialFound = std::any_of(sessionData.AllowedCredentialIDs.value().cbegin(), 
                                            sessionData.AllowedCredentialIDs.value().cend(), 
                                            [&parsedResponseRawID](const std::vector<uint8_t>& allowedCredentialID) { return allowedCredentialID == parsedResponseRawID; });

                if (!credentialFound) {

                    return unexpected(ErrBadRequest().WithDetails("User does not own the credential returned"));
                }
            }

            // Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
            // the owner of the public key credential identified by credential.id.

            // This is in part handled by our Step 1.

            auto userHandle = parsedResponse.Response.UserHandle;
            
            if (!userHandle.empty() && userHandle != user.GetWebAuthNID()) {

                return unexpected(ErrBadRequest().WithDetails("userHandle and User ID do not match"));
            }

            // Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
            // for your use case), look up the corresponding credential public key.
            auto credIter = std::find_if(userCredentials.begin(),
                                         userCredentials.end(),
                                         [&parsedResponseRawID](const CredentialType& userCredential) { return userCredential.ID == parsedResponseRawID; });

            credentialFound = credIter != userCredentials.end();

            if (!credentialFound) {

                return unexpected(ErrBadRequest().WithDetails("Unable to find the credential for the returned credential ID"));
            }
            CredentialType& credential = *credIter;

            auto shouldVerifyUser = (sessionData.UserVerification == Protocol::UserVerificationRequirementType::Required);

            auto rpID = _config.RPID;
            auto rpOrigins = _config.RPOrigins;

            auto appIDResult = parsedResponse.GetAppID(sessionData.Extensions, credential.AttestationType);

            if (!appIDResult) {

                return unexpected(appIDResult.error());
            }
            auto appID = appIDResult.value();

            // Handle steps 4 through 16.
            auto validError = parsedResponse.Verify(sessionData.Challenge, rpID, rpOrigins, appID, shouldVerifyUser, credential.PublicKey);

            if (validError) {

                return unexpected(validError.value());
            }

            // Handle step 17.
            credential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter);

            // TODO: The backup eligible flag shouldn't change. Should decide if we want to error if it does.
            // Update flags from response data.
            credential.Flags.UserPresent = Protocol::HasUserPresent(parsedResponse.Response.AuthenticatorData.Flags);
            credential.Flags.UserVerified = Protocol::HasUserVerified(parsedResponse.Response.AuthenticatorData.Flags);
            credential.Flags.BackupEligible = Protocol::HasBackupEligible(parsedResponse.Response.AuthenticatorData.Flags);
            credential.Flags.BackupState = Protocol::HasBackupState(parsedResponse.Response.AuthenticatorData.Flags);

            return credential;
        }

        ConfigType _config;
    };
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_WEBAUTHN_IPP */
