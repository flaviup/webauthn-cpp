//
//  Registration.cpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#include <cstdarg>
#include "WebAuthN.hpp"
#include "../Protocol/Challenge.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"

namespace WebAuthN::WebAuthN {

#pragma GCC visibility push(hidden)

    namespace {

        inline void _GetDefaultRegistrationCredentialParameters(std::vector<Protocol::CredentialParameterType>& credentialParameters) noexcept {
            
            namespace WebAuthNCOSE = Protocol::WebAuthNCOSE;

            credentialParameters = {
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
        Protocol::expected<CredentialType>
        WebAuthNType::_CreateCredential(const IUser& user, const SessionDataType& sessionData, 
                                        Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept {
            
            if (user.GetWebAuthNID() != sessionData.UserID) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("ID mismatch for User and Session"));
            }

            if (sessionData.Expires != 0ULL && !(sessionData.Expires > time.Now()))) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session has Expired"));
            }

            auto shouldVerifyUser = (sessionData.UserVerification == Protocol::UserVerificationRequirementType::Required);
            auto verificationResult = parsedResponse.Verify(sessionData.Challenge, shouldVerifyUser, _config.RPID, _config.RPOrigins);

            if (verificationResult) {
                return Protocol::unexpected(verificationResult.value());
            }

            return MakeNewCredential(parsedResponse);
        }
    } // namespace

#pragma GCC visibility pop

    // BEGIN REGISTRATION
    // These objects help us create the CredentialCreationOptionsType
    // that will be passed to the authenticator via the user client.

    Protocol::expected<std::pair<Protocol::CredentialCreationType, SessionDataType>>
    WebAuthNType::BeginRegistration(const IUser& user, int optsCount, WebAuthNType::RegistrationOptionHandlerType opts...) noexcept {
        
        auto validationResult = _config.Validate();

        if (validationResult) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
        }

        auto challenge = Protocol::CreateChallenge();

        if (!challenge) {
            return Protocol::unexpected(challenge.error());
        }

        std::string entityUserID{};

        if (_config.EncodeUserIDAsString) {
            entityUserID = std::string(user.GetWebAuthNID());
        } else {
            entityUserID = Protocol::URLEncodedBase64Type(user.GetWebAuthNID());
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

        std::vector<Protocol::CredentialParameterType> credentialParams;
        _GetDefaultRegistrationCredentialParameters(credentialParams);

        auto creation = Protocol::CredentialCreationType{
            Response: Protocol::PublicKeyCredentialCreationOptionsType{
                RelyingParty:           entityRelyingParty,
                User:                   entityUser,
                Challenge:              challenge,
                Parameters:             credentialParams,
                AuthenticatorSelection: Config.AuthenticatorSelection,
                Attestation:            Config.AttestationPreference
            }
        };

        va_list args;
        va_start(args, opts);

        for (int i = 0; i < optsCount; ++i) {
            auto opt = va_arg(args, RegistrationOptionHandlerType);
            opt(creation.Response);
        }

        va_end(args);

        if (creation.Response.Timeout == 0) {

            switch (creation.Response.AuthenticatorSelection.UserVerification) {
                case Protocol::UserVerificationRequirementType::Discouraged:
                    creation.Response.Timeout = int(Config.Timeouts.Registration.Timeout.Milliseconds());
                    break;

                default:
                    creation.Response.Timeout = int(Config.Timeouts.Registration.Timeout.Milliseconds());
                    break;
            }
        }

        auto session = SessionDataType{
            Challenge:        challenge.value(),
            UserID:           user.GetWebAuthNID(),
            UserVerification: creation.Response.AuthenticatorSelection.UserVerification,
        };

        if (Config.Timeouts.Registration.Enforce) {
            session.Expires = time.Now().Add(time.Millisecond * time.Duration(creation.Response.Timeout));
        }

        return std::make_pair(creation, session);
    }

    // WithAuthenticatorSelection adjusts the non-default parameters regarding the authenticator to select during
    // registration.
    inline WebAuthNType::RegistrationOptionHandlerType WithAuthenticatorSelection(const Protocol::AuthenticatorSelectionType& authenticatorSelection) noexcept {

        return [&authenticatorSelection](Protocol::PublicKeyCredentialCreationOptionsType& cco) {


            cco.AuthenticatorSelection = authenticatorSelection;
        };
    }

    // WithExclusions adjusts the non-default parameters regarding credentials to exclude from registration.
    inline WebAuthNType::RegistrationOptionHandlerType WithExclusions(const std::vector<Protocol::CredentialDescriptorType>& excludeList) noexcept {

        return [&excludeList](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

            cco.CredentialExcludeList = excludeList;
        };
    }

    // WithConveyancePreference adjusts the non-default parameters regarding whether the authenticator should attest to the
    // credential.
    inline WebAuthNType::RegistrationOptionHandlerType WithConveyancePreference(Protocol::ConveyancePreferenceType preference) noexcept {

        return [&preference](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

            cco.Attestation = preference;
        };
    }

    // WithExtensions adjusts the extension parameter in the registration options.
    inline WebAuthNType::RegistrationOptionHandlerType WithExtensions(const Protocol::AuthenticationExtensionsType& extensions) noexcept {

        return [&extensions](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

            cco.Extensions = extensions;
        };
    }

    // WithCredentialParameters adjusts the credential parameters in the registration options.
    inline WebAuthNType::RegistrationOptionHandlerType WithCredentialParameters(const std::vector<Protocol::CredentialParameterType>& credentialParams) noexcept {

        return [&credentialParams](Protocol::PublicKeyCredentialCreationOptionsType& cco) {

            cco.Parameters = credentialParams;
        };
    }

    // WithAppIdExcludeExtension automatically includes the specified appid if the CredentialExcludeList contains a credential
    // with the type `fido-u2f`.
    inline WebAuthNType::RegistrationOptionHandlerType WithAppIdExcludeExtension(const std::string& appid) noexcept {

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
    inline WebAuthNType::RegistrationOptionHandlerType WithResidentKeyRequirement(Protocol::ResidentKeyRequirementType requirement) noexcept {

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

    Protocol::expected<CredentialType>
    WebAuthNType::FinishRegistration(const IUser& user, const SessionDataType& sessionData, const std::string& response) noexcept {
        
        auto parsedResponse = Protocol::ParseCredentialCreationResponse(response);

        if (!parsedResponse) {
            return Protocol::unexpected(parsedResponse.error());
        }

        return _CreateCredential(user, sessionData, parsedResponse);
    }
} // namespace WebAuthN::WebAuthN
