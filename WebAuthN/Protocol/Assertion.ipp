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
#include "Client.ipp"
#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // ParsedAssertionResponseType is the parsed form of AuthenticatorAssertionResponseType.
    struct ParsedAssertionResponseType {

        ParsedAssertionResponseType() noexcept = default;
        ParsedAssertionResponseType(const ParsedAssertionResponseType& parsedAssertionResponse) noexcept = default;
        ParsedAssertionResponseType(ParsedAssertionResponseType&& parsedAssertionResponse) noexcept = default;
        ~ParsedAssertionResponseType() noexcept = default;

        ParsedAssertionResponseType& operator =(const ParsedAssertionResponseType& other) noexcept = default;
        ParsedAssertionResponseType& operator =(ParsedAssertionResponseType&& other) noexcept = default;

        CollectedClientDataType CollectedClientData;
        AuthenticatorDataType AuthenticatorData;
        std::vector<uint8_t> Signature;
        std::vector<uint8_t> UserHandle;
    };

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
        AuthenticatorAssertionResponseType(const AuthenticatorAssertionResponseType& authenticatorAssertionResponse) noexcept = default;
        AuthenticatorAssertionResponseType(AuthenticatorAssertionResponseType&& authenticatorAssertionResponse) noexcept = default;
        ~AuthenticatorAssertionResponseType() noexcept override = default;

        AuthenticatorAssertionResponseType& operator =(const AuthenticatorAssertionResponseType& other) noexcept = default;
        AuthenticatorAssertionResponseType& operator =(AuthenticatorAssertionResponseType&& other) noexcept = default;

        // Parse the values returned in the authenticator response and perform attestation verification
        // Step 8. This returns a fully decoded struct with the data put into a format that can be
        // used to verify the user and credential that was created.
        inline expected<ParsedAssertionResponseType> Parse() const {
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

    // The CredentialAssertionResponseType is the raw response returned to the Relying Party from an authenticator when we request a
    // credential for login/assertion.
    struct CredentialAssertionResponseType : public PublicKeyCredentialType {

        CredentialAssertionResponseType() noexcept = default;
        CredentialAssertionResponseType(const json& j) :
            PublicKeyCredentialType(j),
            AssertionResponse(j["response"]) {
        }
        CredentialAssertionResponseType(const CredentialAssertionResponseType& credentialAssertionResponse) noexcept = default;
        CredentialAssertionResponseType(CredentialAssertionResponseType&& credentialAssertionResponse) noexcept = default;
        ~CredentialAssertionResponseType() noexcept override = default;

        CredentialAssertionResponseType& operator =(const CredentialAssertionResponseType& other) noexcept = default;
        CredentialAssertionResponseType& operator =(CredentialAssertionResponseType&& other) noexcept = default;

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
        ParsedCredentialAssertionDataType(const ParsedPublicKeyCredentialType& ppkc,
            const ParsedAssertionResponseType& response,
            const CredentialAssertionResponseType& raw) noexcept : 
            ParsedPublicKeyCredentialType(ppkc),
            Response(response),
            Raw(raw) {
        };
        ParsedCredentialAssertionDataType(const json& j) :
            ParsedPublicKeyCredentialType(j) {
        }
        ParsedCredentialAssertionDataType(const ParsedCredentialAssertionDataType& parsedCredentialAssertionData) noexcept = default;
        ParsedCredentialAssertionDataType(ParsedCredentialAssertionDataType&& parsedCredentialAssertionData) noexcept = default;
        ~ParsedCredentialAssertionDataType() noexcept override = default;

        ParsedCredentialAssertionDataType& operator =(const ParsedCredentialAssertionDataType& other) noexcept = default;
        ParsedCredentialAssertionDataType& operator =(ParsedCredentialAssertionDataType&& other) noexcept = default;

        // Parse validates and parses the CredentialAssertionResponseType into a ParsedCredentialCreationDataType.
        inline static expected<ParsedCredentialAssertionDataType> Parse(const CredentialAssertionResponseType& credentialAssertionResponse) noexcept {

            if (credentialAssertionResponse.ID.empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo("Missing ID"));
            }
            auto testB64Result = URLEncodedBase64_Decode(credentialAssertionResponse.ID);

            if (!testB64Result || testB64Result.value().empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo("ID not base64 URL Encoded"));
            }

            if (credentialAssertionResponse.Type.empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo("Missing type"));
            }

            if (json(credentialAssertionResponse.Type).get<CredentialTypeType>() != CredentialTypeType::PublicKey) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo(fmt::format("Type not {}", json(CredentialTypeType::PublicKey))));
            }

            auto responseParseResult = credentialAssertionResponse.AssertionResponse.Parse();
            
            if (!responseParseResult) {
                return unexpected(ErrParsingData().WithDetails("Error parsing assertion response"));
            }
            auto response = responseParseResult.value();
            auto attachment = json(credentialAssertionResponse.AuthenticatorAttachment.value()).get<AuthenticatorAttachmentType>();

            return ParsedCredentialAssertionDataType{
                ParsedPublicKeyCredentialType{
                    ParsedCredentialType{
                        credentialAssertionResponse.ID, 
                        credentialAssertionResponse.Type
                    },
                    std::vector<uint8_t>(credentialAssertionResponse.RawID.begin(), credentialAssertionResponse.RawID.end()),
                    credentialAssertionResponse.ClientExtensionResults,
                    std::optional<AuthenticatorAttachmentType>(attachment)
                },
                response,
                credentialAssertionResponse
            };
        }

        // Verify the remaining elements of the assertion data by following the steps outlined in the referenced specification
        // documentation.
        //
        // Specification: §7.2 Verifying an Authentication Assertion (https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)
        inline std::optional<ErrorType> Verify(const std::string& storedChallenge, 
            const std::string& relyingPartyID, 
            const std::vector<std::string>& relyingPartyOrigins, 
            const std::string& appID,
            bool verifyUser, 
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

    inline expected<ParsedCredentialAssertionDataType> ParseCredentialRequestResponse(const std::string& response) noexcept {

        if (response.empty()) {
            return unexpected(ErrBadRequest().WithDetails("No response given"));
        }

        try {

            auto credentialAssertionResponse = json(response).get<CredentialAssertionResponseType>();
            return ParsedCredentialAssertionDataType::Parse(credentialAssertionResponse);
        } catch(const std::exception& e) {
            return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo(e.what()));
        }
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ASSERTION_IPP */
