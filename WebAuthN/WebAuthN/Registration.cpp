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

        int64_t _Timestamp() noexcept
        {
            const auto now = std::chrono::system_clock::now();

            // transform the time into a duration since the epoch
            const auto epoch = now.time_since_epoch();

            // cast the duration into milliseconds
            const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);

            // return the number of milliseconds
            return millis.count();
        }

        // CreateCredential verifies a parsed response against the user's credentials and session data.
        Protocol::expected<CredentialType>
        WebAuthNType::_CreateCredential(const IUser& user, const SessionDataType& sessionData, 
                                        Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept {
            
            if (user.GetWebAuthNID() != sessionData.UserID) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("ID mismatch for User and Session"));
            }

            if (sessionData.Expires != 0LL && sessionData.Expires <= _Timestamp()) {
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
    WebAuthNType::BeginRegistration(const IUser& user, int optsCount, const WebAuthNType::RegistrationOptionHandlerType& opts...) noexcept {
        
        auto validationResult = _config.Validate();

        if (validationResult) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
        }

        auto challenge = Protocol::CreateChallenge();

        if (!challenge) {
            return Protocol::unexpected(challenge.error());
        }

        Protocol::URLEncodedBase64Type entityUserID{};

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
            Protocol::PublicKeyCredentialCreationOptionsType{
                entityRelyingParty,
                entityUser,
                challenge.value(),
                credentialParams,
                std::nullopt,
                std::nullopt,
                _config.AuthenticatorSelection,
                _config.AttestationPreference
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
            challenge.value(),
            user.GetWebAuthNID(),
            "",
            _config.Timeouts.Registration.Enforce ? _Timestamp() + creation.Response.Timeout.value() : 0,
            creation.Response.AuthenticatorSelection.value().UserVerification.value()
        };

        return std::make_pair(creation, session);
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
