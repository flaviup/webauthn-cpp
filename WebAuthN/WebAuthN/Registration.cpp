//
//  Registration.cpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#include "WebAuthN.hpp"
#include "../Protocol/Challenge.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"
#include "../Util/Time.ipp"

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
        WebAuthNType::_CreateCredential(const IUser& user,
                                        const SessionDataType& sessionData, 
                                        const Protocol::ParsedCredentialCreationDataType& parsedResponse) noexcept {
            
            if (user.GetWebAuthNID() != sessionData.UserID) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("ID mismatch for User and Session"));
            }

            if (sessionData.Expires != 0LL && sessionData.Expires <= Util::Time::Timestamp()) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session has Expired"));
            }

            auto shouldVerifyUser = (sessionData.UserVerification == Protocol::UserVerificationRequirementType::Required);
            auto verificationResultError = parsedResponse.Verify(sessionData.Challenge, shouldVerifyUser, _config.RPID, _config.RPOrigins);

            if (verificationResultError) {
                return Protocol::unexpected(verificationResultError.value());
            }

            return MakeNewCredential(parsedResponse);
        }
    } // namespace

#pragma GCC visibility pop

    // BEGIN REGISTRATION
    // These objects help us create the CredentialCreationOptionsType
    // that will be passed to the authenticator via the user client.

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialCreationType, SessionDataType>>
    WebAuthNType::BeginRegistration(const IUser& user, const WebAuthNType::RegistrationOptionHandlerType (&opts)[N] = WebAuthNType::RegistrationOptionHandlerType[]{}) noexcept {
        
        auto validationResult = _config.Validate();

        if (validationResult) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
        }
        Protocol::URLEncodedBase64Type challenge;
        auto challengeCreationError = Protocol::CreateChallenge(challenge);

        if (challengeCreationError) {
            return Protocol::unexpected(challengeCreationError.value());
        }

        Protocol::URLEncodedBase64Type entityUserID{};

        if (_config.EncodeUserIDAsString) {
            entityUserID = std::string(user.GetWebAuthNID());
        } else {
            auto idEncodingError = Protocol::URLEncodedBase64_Encode(user.GetWebAuthNID(), entityUserID);

            if (idEncodingError) {
                return Protocol::unexpected(idEncodingError.value());
            }
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
            challenge,
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

        return _CreateCredential(user, sessionData, parsedResponse.value());
    }
} // namespace WebAuthN::WebAuthN
