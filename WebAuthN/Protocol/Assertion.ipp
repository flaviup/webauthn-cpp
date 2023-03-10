//
//  Assertion.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/19/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ASSERTION_IPP
#define WEBAUTHN_PROTOCOL_ASSERTION_IPP

#include <algorithm>
#include <fmt/format.h>
#include "Client.ipp"
#include "Credential.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Structs

    // ParsedAssertionResponseType is the parsed form of AuthenticatorAssertionResponseType.
    struct ParsedAssertionResponseType {

        ParsedAssertionResponseType() noexcept = default;

        ParsedAssertionResponseType(const CollectedClientDataType& collectedClientData,
            const AuthenticatorDataType& authenticatorData,
            const std::vector<uint8_t>& signature,
            const std::vector<uint8_t>& userHandle) noexcept : 
            CollectedClientData(collectedClientData),
            AuthenticatorData(authenticatorData),
            Signature(signature),
            UserHandle(userHandle) {
        }

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
        inline expected<ParsedAssertionResponseType> Parse() const noexcept {

            // Step 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
            // We don't call it cData but this is Step 5 in the spec.
            auto decodedClientData = URLEncodedBase64_Decode(ClientDataJSON);

            if (!decodedClientData) {
                return unexpected(ErrParsingData().WithDetails("Error unmarshalling client data json"));
            }
            auto collectedClientData = decodedClientData.value(); // WebAuthNCBOR::JsonUnmarshal(decodedClientData.value());
            AuthenticatorDataType auth{};
            auto binaryData = URLEncodedBase64_DecodeAsBinary(AuthenticatorData);

            if (!binaryData || auth.Unmarshal(binaryData.value())) {
                return unexpected(ErrParsingData().WithDetails("Error unmarshalling auth data"));
            }
            binaryData = URLEncodedBase64_DecodeAsBinary(Signature);

            if (!binaryData) {
                return unexpected(ErrParsingData().WithDetails("Error unmarshalling signature"));
            }
            auto signature = binaryData.value();
            std::vector<uint8_t> userHandle{};

            if (UserHandle) {
                binaryData = URLEncodedBase64_DecodeAsBinary(UserHandle.value());

                if (!binaryData) {
                    return unexpected(ErrParsingData().WithDetails("Error unmarshalling user handle"));
                }
                userHandle = binaryData.value();
            }

            return ParsedAssertionResponseType{
                json::parse(collectedClientData).get<CollectedClientDataType>(),
                auth,
                signature,
                userHandle
            };
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
        j.at("signature").get_to(authenticatorAssertionResponse.Signature);

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
        }

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
                return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion")
                                                 .WithInfo(fmt::format("Type not {}",
                                                                       json(CredentialTypeType::PublicKey).get<std::string>())));
            }

            auto responseParseResult = credentialAssertionResponse.AssertionResponse.Parse();
            
            if (!responseParseResult) {
                return unexpected(ErrParsingData().WithDetails("Error parsing assertion response"));
            }
            auto response = responseParseResult.value();

            return ParsedCredentialAssertionDataType{
                ParsedPublicKeyCredentialType{
                    ParsedCredentialType{
                        credentialAssertionResponse.ID, 
                        credentialAssertionResponse.Type
                    },
                    URLEncodedBase64_DecodeAsBinary(credentialAssertionResponse.RawID).value(),
                    credentialAssertionResponse.ClientExtensionResults,
                    credentialAssertionResponse.AuthenticatorAttachment
                },
                response,
                credentialAssertionResponse
            };
        }

        // Verify the remaining elements of the assertion data by following the steps outlined in the referenced specification
        // documentation.
        //
        // Specification: §7.2 Verifying an Authentication Assertion (https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)
        inline std::optional<ErrorType>
        Verify(const std::string& storedChallenge, 
               const std::string& relyingPartyID, 
               const std::vector<std::string>& relyingPartyOrigins, 
               const std::string& appID,
               bool verifyUser, 
               const std::vector<uint8_t>& credentialBytes) const noexcept {

            // Steps 4 through 6 in verifying the assertion data (https://www.w3.org/TR/webauthn/#verifying-assertion) are
            // "assertive" steps, i.e "Let JSONtext be the result of running UTF-8 decode on the value of cData."
            // We handle these steps in part as we verify but also beforehand

            // Handle steps 7 through 10 of assertion by verifying stored data against the Collected Client Data
            // returned by the authenticator
            auto err = Response.CollectedClientData.Verify(storedChallenge, CeremonyType::Assert, relyingPartyOrigins);

            if (err) {
                return err;
            }

            // Begin Step 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the RP.
            auto rpIDHash = Util::Crypto::SHA256(relyingPartyID);
            std::vector<uint8_t> appIDHash{};

            if (!appID.empty()) {
                appIDHash = Util::Crypto::SHA256(appID);
            }

            // Handle steps 11 through 14, verifying the authenticator data.
            err = Response.AuthenticatorData.Verify(rpIDHash, appIDHash, verifyUser);

            if (err) {
                return err;
            }

            auto decodedAuthenticatorData = URLEncodedBase64_DecodeAsBinary(Raw.AssertionResponse.AuthenticatorData);

            if (!decodedAuthenticatorData) {
                return decodedAuthenticatorData.error();
            }
            auto authenticatorData = decodedAuthenticatorData.value();

            auto decodedClientDataJson = URLEncodedBase64_Decode(Raw.AssertionResponse.ClientDataJSON);

            if (!decodedClientDataJson) {
                return decodedClientDataJson.error();
            }

            // Step 15. Let hash be the result of computing a hash over the cData using SHA-256.
            auto clientDataHash = Util::Crypto::SHA256(decodedClientDataJson.value());

            // Step 16. Using the credential public key looked up in step 3, verify that sig is
            // a valid signature over the binary concatenation of authData and hash.
            std::vector<uint8_t> sigData(authenticatorData.size() + clientDataHash.size());
            std::memcpy(sigData.data(), authenticatorData.data(), authenticatorData.size());
            std::memcpy(sigData.data() + authenticatorData.size(), clientDataHash.data(), clientDataHash.size());

            // If the Session Data does not contain the appID extension or it wasn't reported as used by the Client/RP then we
            // use the standard CTAP2 public key parser.
            std::vector<uint8_t> data{};
            std::any key;

            if (appID.empty()) {

                auto result = WebAuthNCOSE::ParsePublicKey(credentialBytes);

                if (!result) {
                    err = result.error();
                } else {
                    key = result.value();
                }
            } else {

                auto result = WebAuthNCOSE::ParseFIDOPublicKey(credentialBytes);

                if (!result) {
                    err = result.error();
                } else {
                    key = result.value();
                }
            }

            if (err) {
                return ErrAssertionSignature().WithDetails(fmt::format("Error parsing the assertion public key: {}", std::string(err.value())));
            }

            auto errSig = WebAuthNCOSE::VerifySignature(key, sigData, Response.Signature);

            if (!errSig) {
                return ErrAssertionSignature().WithDetails(fmt::format("Error validating the assertion signature: {}", std::string(errSig.error())));
            }

            return std::nullopt;
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

    // Functions

    inline expected<ParsedCredentialAssertionDataType> ParseCredentialRequestResponse(const std::string& response) noexcept {

        if (response.empty()) {
            return unexpected(ErrBadRequest().WithDetails("No response given"));
        }

        try {

            auto credentialAssertionResponse = json::parse(response).get<CredentialAssertionResponseType>();
            return ParsedCredentialAssertionDataType::Parse(credentialAssertionResponse);
        } catch (const std::exception& e) {
            return unexpected(ErrBadRequest().WithDetails("Parse error for Assertion").WithInfo(e.what()));
        }
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ASSERTION_IPP */
