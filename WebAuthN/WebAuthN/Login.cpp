//
//  Login.cpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/24/23.
//  flaviup on gmail com
//

#include "WebAuthN.hpp"
#include "../Protocol/Challenge.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"

namespace WebAuthN::WebAuthN {

#pragma GCC visibility push(hidden)

    namespace {

    } // namespace

#pragma GCC visibility pop

    // BEGIN LOGIN
    // These objects help us create the PublicKeyCredentialRequestOptionsType
    // that will be passed to the authenticator via the user client.

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::BeginLogin(const IUser& user, const WebAuthNType::LoginOptionHandlerType (&opts)[N] = WebAuthNType::LoginOptionHandlerType[]{}) noexcept {

        auto credentials = user.GetWebAuthNCredentials();

        if (credentials.empty()) { // If the user does not have any credentials, we cannot perform an assertion.
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Found no credentials for user"));
        }

        std::vector<Protocol::CredentialDescriptorType> allowedCredentials(credentials.size());

        for (const auto& credential : credentials) {
            allowedCredentials.push_back(credential.Descriptor());
        }

        return _BeginLogin(user.GetWebAuthNID(), allowedCredentials, opts);
    }

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::BeginDiscoverableLogin(const WebAuthNType::LoginOptionHandlerType (&opts)[N] = WebAuthNType::LoginOptionHandlerType[]{}) noexcept {

        return _BeginLogin(std::nullopt, std::nullopt, opts;
    }

    template<size_t N>
    Protocol::expected<std::pair<Protocol::CredentialAssertionType, SessionDataType>>
    WebAuthNType::_BeginLogin(const std::optional<std::vector<uint8_t>>& userID, 
                              const std::optional<std::vector<Protocol::CredentialDescriptorType>>& allowedCredentials, 
                              const WebAuthNType::LoginOptionHandlerType (&opts)[N] = WebAuthNType::LoginOptionHandlerType[]{}) noexcept {

        auto validationResult = _config.Validate();

        if (validationResult) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, validationResult.value()));
        }

        URLEncodedBase64Type challenge;
        auto challengeCreationError = Protocol::CreateChallenge(challenge);

        if (challengeCreationError) {
            return Protocol::unexpected(challengeCreationError.value());
        }

        auto assertion = Protocol::CredentialAssertionType{
            Response: Protocol::PublicKeyCredentialRequestOptionsType{
                Challenge:          challenge,
                RelyingPartyID:     _config.RPID,
                UserVerification:   _config.AuthenticatorSelection.UserVerification,
                AllowedCredentials: allowedCredentials
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
            _config.Timeouts.Login.Enforce ? _Timestamp() + assertion.Response.Timeout.value() : 0,
            assertion.Response.UserVerification.value(),
            assertion.Response.GetAllowedCredentialIDs(),
            assertion.Response.Extensions.value()
        };

        return std::make_pair(assertion, session);
    }

    Protocol::expected<CredentialType>
    WebAuthNType::FinishLogin(const IUser& user, const SessionDataType& sessionData, const std::string& response) noexcept {

        auto parsedResponse = Protocol::ParseCredentialRequestResponse(response);

        if (!parsedResponse) {
            return Protocol::unexpected(parsedResponse.error());
        }

        return ValidateLogin(user, sessionData, parsedResponse.value());
    }

    Protocol::expected<CredentialType>
    WebAuthNType::ValidateLogin(const IUser& user, const SessionDataType& sessionData, const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
        
        if (user.GetWebAuthNID() != sessionData.UserID) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("ID mismatch for User and Session"));
        }

        if (sessionData.Expires != 0LL && sessionData.Expires <= _Timestamp()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session has Expired"));
        }

        return _ValidateLogin(user, sessionData, parsedResponse);
    }

    Protocol::expected<CredentialType>
    WebAuthNType::ValidateDiscoverableLogin(WebAuthNType::DiscoverableUserHandlerType handler, 
                                            const SessionDataType& sessionData, 
                                            const Protocol::ParsedCredentialAssertionDataType& parsedResponse) noexcept {
        if (!sessionData.UserID.empty()) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Session was not initiated as a client-side discoverable login"));
        }

        if (parsedResponse.Response.UserHandle == nil) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Client-side Discoverable Assertion was attempted with a blank User Handle"));
        }

        auto handlerResult = handler(parsedResponse.RawID, parsedResponse.Response.UserHandle);

        if (!handlerResult) {
            return Protocol::unexpected(Protocol::ErrBadRequest().WithDetails("Failed to lookup Client-side Discoverable Credential"));
        }

        return _ValidateLogin(handlerResult.value(), sessionData, parsedResponse);
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
        bool credentialFound = false;

        if len(session.AllowedCredentialIDs) > 0 {
            var credentialsOwned bool

            for _, allowedCredentialID := range session.AllowedCredentialIDs {
                for _, userCredential := range userCredentials {
                    if bytes.Equal(userCredential.ID, allowedCredentialID) {
                        credentialsOwned = true

                        break
                    }

                    credentialsOwned = false
                }
            }

            if !credentialsOwned {
                return nil, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowedCredentialList")
            }

            for _, allowedCredentialID := range session.AllowedCredentialIDs {
                if bytes.Equal(parsedResponse.RawID, allowedCredentialID) {
                    credentialFound = true

                    break
                }
            }

            if !credentialFound {
                return nil, protocol.ErrBadRequest.WithDetails("User does not own the credential returned")
            }
        }

        // Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
        // the owner of the public key credential identified by credential.id.

        // This is in part handled by our Step 1.

        userHandle := parsedResponse.Response.UserHandle
        if len(userHandle) > 0 {
            if !bytes.Equal(userHandle, user.WebAuthnID()) {
                return nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
            }
        }

        // Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
        // for your use case), look up the corresponding credential public key.
        var loginCredential Credential

        for _, cred := range userCredentials {
            if bytes.Equal(cred.ID, parsedResponse.RawID) {
                loginCredential = cred
                credentialFound = true

                break
            }

            credentialFound = false
        }

        if !credentialFound {
            return nil, protocol.ErrBadRequest.WithDetails("Unable to find the credential for the returned credential ID")
        }

        shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

        rpID := webauthn.Config.RPID
        rpOrigins := webauthn.Config.RPOrigins

        appID, err := parsedResponse.GetAppID(session.Extensions, loginCredential.AttestationType)
        if err != nil {
            return nil, err
        }

        // Handle steps 4 through 16.
        validError := parsedResponse.Verify(session.Challenge, rpID, rpOrigins, appID, shouldVerifyUser, loginCredential.PublicKey)
        if validError != nil {
            return nil, validError
        }

        // Handle step 17.
        loginCredential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)

        // TODO: The backup eligible flag shouldn't change. Should decide if we want to error if it does.
        // Update flags from response data.
        loginCredential.Flags.UserPresent = parsedResponse.Response.AuthenticatorData.Flags.HasUserPresent()
        loginCredential.Flags.UserVerified = parsedResponse.Response.AuthenticatorData.Flags.HasUserVerified()
        loginCredential.Flags.BackupEligible = parsedResponse.Response.AuthenticatorData.Flags.HasBackupEligible()
        loginCredential.Flags.BackupState = parsedResponse.Response.AuthenticatorData.Flags.HasBackupState()

        return &loginCredential, nil
    }

} // namespace WebAuthN::WebAuthN
