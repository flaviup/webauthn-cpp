//
//  Login.cpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/24/23.
//  flaviup on gmail com
//

#include "WebAuthN.hpp"
#include "../Protocol/Challenge.ipp"
#include "../Protocol/Options.ipp"
#include "../Util/Time.ipp"

namespace WebAuthN::WebAuthN {

    // BEGIN LOGIN
    // These objects help us create the PublicKeyCredentialRequestOptionsType
    // that will be passed to the authenticator via the user client.

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::BeginLogin(const IUser& user,
                             const WebAuthNType::LoginOptionHandlerType (&opts)[N]) noexcept {

        auto credentials = user.GetWebAuthNCredentials();

        if (credentials.empty()) { // If the user does not have any credentials, we cannot perform an assertion.
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Found no credentials for user"));
        }

        std::vector<Protocol::CredentialDescriptorType> allowedCredentials(credentials.size());

        for (const auto& credential : credentials) {
            allowedCredentials.push_back(credential.ToDescriptorType());
        }

        return _BeginLogin(user.GetWebAuthNID(), allowedCredentials, opts);
    }

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::BeginDiscoverableLogin(const WebAuthNType::LoginOptionHandlerType (&opts)[N]) noexcept {

        return _BeginLogin(std::nullopt, std::nullopt, opts);
    }

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::_BeginLogin(const std::optional<std::vector<uint8_t>>& userID,
                              const std::optional<std::vector<Protocol::CredentialDescriptorType>>& allowedCredentials,
                              const WebAuthNType::LoginOptionHandlerType (&opts)[N]) noexcept {

        auto validationResult = _config.Validate();

        if (validationResult) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
        }

        auto challengeCreationResult = Protocol::CreateChallenge();

        if (!challengeCreationResult) {
            return Protocol::unexpected(challengeCreationResult.error());
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

        if (assertion.Response.Timeout == 0) {

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
            "",
            _config.Timeouts.Login.Enforce ? Util::Time::Timestamp() + assertion.Response.Timeout.value() : 0,
            assertion.Response.UserVerification.value(),
            assertion.Response.GetAllowedCredentialIDs(),
            assertion.Response.Extensions
        };

        return std::make_pair(assertion, session);
    }

    Protocol::expected<CredentialType>
    WebAuthNType::FinishLogin(const IUser& user, 
                              const SessionDataType& sessionData, 
                              const std::string& response) noexcept {

        auto parsedResponse = Protocol::ParseCredentialRequestResponse(response);   

        if (!parsedResponse) {
            return Protocol::unexpected(parsedResponse.error());
        }

        return ValidateLogin(user, sessionData, parsedResponse.value());
    }

    Protocol::expected<CredentialType>
    WebAuthNType::ValidateLogin(const IUser& user, 
                                const SessionDataType& sessionData, 
                                const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
        
        if (user.GetWebAuthNID() != sessionData.UserID) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("ID mismatch for User and Session"));
        }

        if (sessionData.Expires != 0LL && sessionData.Expires <= Util::Time::Timestamp()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session has Expired"));
        }

        return _ValidateLogin(user, sessionData, parsedResponse);
    }

    Protocol::expected<CredentialType>
    WebAuthNType::ValidateDiscoverableLogin(const WebAuthNType::DiscoverableUserHandlerType handler, 
                                            const SessionDataType& sessionData, 
                                            const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
        if (sessionData.UserID && !sessionData.UserID.value().empty()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session was not initiated as a client-side discoverable login"));
        }

        if (parsedResponse.Response.UserHandle.empty()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Client-side Discoverable Assertion was attempted with a blank User Handle"));
        }

        auto handlerResult = handler(parsedResponse.RawID, parsedResponse.Response.UserHandle);

        if (!handlerResult || handlerResult.value() == nullptr) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Failed to lookup Client-side Discoverable Credential"));
        }

        return _ValidateLogin(*handlerResult.value(), sessionData, parsedResponse);
    }

    Protocol::expected<CredentialType>
    WebAuthNType::_ValidateLogin(const IUser& user,
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
                                                    [&allowedCredentialID](const std::vector<uint8_t>& userCredential) { return userCredential == allowedCredentialID; });

                if (!credentialsOwned) {
                    return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("User does not own all credentials from the allowedCredentialList"));
                }
            }

            credentialFound = std::any_of(sessionData.AllowedCredentialIDs.value().cbegin(), 
                                          sessionData.AllowedCredentialIDs.value().cend(), 
                                          [&parsedResponseRawID](const std::vector<uint8_t>& allowedCredentialID) { return allowedCredentialID == parsedResponseRawID; });

            if (!credentialFound) {
                return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("User does not own the credential returned"));
            }
        }

        // Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
        // the owner of the public key credential identified by credential.id.

        // This is in part handled by our Step 1.

        auto userHandle = parsedResponse.Response.UserHandle;
        
        if (!userHandle.empty() && userHandle != user.GetWebAuthNID()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("userHandle and User ID do not match"));
        }

        // Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
        // for your use case), look up the corresponding credential public key.
        auto credIter = std::find_if(userCredentials.begin(),
                                     userCredentials.end(),
                                     [&parsedResponseRawID](const std::vector<uint8_t>& userCredential) { return userCredential == parsedResponseRawID; });

        credentialFound = credIter != userCredentials.end();

        if (!credentialFound) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Unable to find the credential for the returned credential ID"));
        }
        CredentialType& credential = *credIter;

        auto shouldVerifyUser = (sessionData.UserVerification == Protocol::UserVerificationRequirementType::Required);

        auto rpID = _config.RPID;
        auto rpOrigins = _config.RPOrigins;

        auto appIDResult = parsedResponse.GetAppID(sessionData.Extensions, credential.AttestationType);

        if (!appIDResult) {
            return Protocol::unexpected(appIDResult.error());
        }
        auto appID = appIDResult.value();

        // Handle steps 4 through 16.
        auto validError = parsedResponse.Verify(sessionData.Challenge, rpID, rpOrigins, appID, shouldVerifyUser, credential.PublicKey);

        if (validError) {
            return Protocol::unexpected(validError.value());
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
} // namespace WebAuthN::WebAuthN
