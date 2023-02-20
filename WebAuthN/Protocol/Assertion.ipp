//
//  Assertion.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/19/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ASSERTION_IPP
#define WEBAUTHN_PROTOCOL_ASSERTION_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "Base64.ipp"
#include "Errors.ipp"
#include "Extensions.ipp"
#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // The CredentialAssertionResponseType is the raw response returned to the Relying Party from an authenticator when we request a
    // credential for login/assertion.
    struct CredentialAssertionResponseType : public PublicKeyCredentialType {

        CredentialAssertionResponseType() noexcept = default;
        CredentialAssertionResponseType(const json& j) :
            PublicKeyCredentialType(j),
            AssertionResponse(j["response"]) {
        }

        AuthenticatorAssertionResponseType AssertionResponse;
    };

    inline void to_json(json& j, const CredentialAssertionResponseType& credentialAssertionResponse) {
        json _j;
        to_json(_j, static_cast<const PublicKeyCredentialType&>(credentialAssertionResponse));
        _j["response"] = credentialAssertionResponse.AssertionResponse;
        j = _j;
    }

    inline void from_json(const json& j, CredentialAssertionResponseType& credentialAssertionResponse) {
        from_json(j, static_cast<PublicKeyCredentialType&>(credentialAssertionResponse));
        j.at("response").get_to(credentialAssertionResponse.AssertionResponse);
    }

    // The ParsedCredentialAssertionDataType is the parsed CredentialAssertionResponseType that has been marshalled into a format
    // that allows us to verify the client and authenticator data inside the response.
    struct ParsedCredentialAssertionDataType : public ParsedPublicKeyCredentialType {

        ParsedCredentialAssertionDataType() noexcept = default;
        ParsedCredentialAssertionDataType(const json& j) :
            ParsedPublicKeyCredentialType(j) {
        }

        // Verify the remaining elements of the assertion data by following the steps outlined in the referenced specification
        // documentation.
        //
        // Specification: §7.2 Verifying an Authentication Assertion (https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)
        inline std::optional<ErrorType> Verify(const std::string& storedChallenge, 
            const std::string& relyingPartyID, 
            const std::vector<std::string>& relyingPartyOrigins, 
            const std::string& appID, bool verifyUser, 
            const std::vector<uint8_t>& credentialBytes) const {
        }

        ParsedAssertionResponseType Response;
        CredentialAssertionResponseType Raw;
    };

    inline void to_json(json& j, const ParsedCredentialAssertionDataType& parsedCredentialAssertionData) {
        to_json(j, static_cast<const ParsedPublicKeyCredentialType&>(parsedCredentialAssertionData));
    }

    inline void from_json(const json& j, ParsedCredentialAssertionDataType& parsedCredentialAssertionData) {
        from_json(j, static_cast<ParsedPublicKeyCredentialType&>(parsedCredentialAssertionData));
    }

    // The AuthenticatorAssertionResponseType contains the raw authenticator assertion data and is parsed into
    // ParsedAssertionResponseType.
    struct AuthenticatorAssertionResponseType : public AuthenticatorResponseType {

	    AuthenticatorAssertionResponseType() noexcept = default;
        AuthenticatorAssertionResponseType(const json& j) :
            AuthenticatorResponseType(j),
            AuthenticatorData(j["authenticatorData"].get<URLEncodedBase64Type>()),
            Signature(j["signature"].get<URLEncodedBase64Type>()) {

            if (j.find("userHandle") != j.end()) {
                UserHandle.emplace(j["userHandle"].get<URLEncodedBase64Type>());
            }
        }

	    URLEncodedBase64Type AuthenticatorData;
	    URLEncodedBase64Type Signature;
	    std::optional<URLEncodedBase64Type> UserHandle; 
    };

    inline void to_json(json& j, const AuthenticatorAssertionResponseType& authenticatorAssertionResponse) {
        json _j;
        to_json(_j, static_cast<const AuthenticatorResponseType&>(authenticatorAssertionResponse));
        _j["authenticatorData"] = authenticatorAssertionResponse.AuthenticatorData;
        _j["signature"] = authenticatorAssertionResponse.Signature;

        if (authenticatorAssertionResponse.UserHandle) {
            _j["userHandle"] = authenticatorAssertionResponse.UserHandle.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, AuthenticatorAssertionResponseType& authenticatorAssertionResponse) {
        from_json(j, static_cast<AuthenticatorResponseType&>(authenticatorAssertionResponse));
        j.at("authenticatorData").get_to(authenticatorAssertionResponse.AuthenticatorData);

        if (j.find("userHandle") != j.end()) {
            authenticatorAssertionResponse.UserHandle.emplace(j["userHandle"].get<URLEncodedBase64Type>());
        }
    }

    // ParsedAssertionResponseType is the parsed form of AuthenticatorAssertionResponseType.
    struct ParsedAssertionResponseType {
	    
        ParsedAssertionResponseType() noexcept = default;

        CollectedClientDataType CollectedClientData;
	    AuthenticatorDataType AuthenticatorData;
	    std::vector<uint8_t> Signature;
	    std::vector<uint8_t> UserHandle;
    };

} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ASSERTION_IPP */
