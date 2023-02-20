//
//  Client.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CLIENT_IPP
#define WEBAUTHN_PROTOCOL_CLIENT_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "Authenticator.ipp"
#include "Extensions.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    enum class CeremonyType {

        Create,
        Assert,
        Invalid = -1 // Invalid value
    };

    // map CeremonyType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(CeremonyType, {
        {CeremonyType::Invalid, nullptr},
        {CeremonyType::Invalid, ""},
        {CeremonyType::Create, "webauthn.create"},
        {CeremonyType::Assert, "webauthn.get"}
    })

    enum class TokenBindingStatusType {

        // Indicates token binding was used when communicating with the
	    // Relying Party. In this case, the id member MUST be present.
        Present,

	    // Indicates token binding was used when communicating with the
	    // negotiated when communicating with the Relying Party.
        Supported,

        // Indicates token binding not supported
	    // when communicating with the Relying Party.
        NotSupported,

        // Invalid value
        Invalid = -1
    };

    // map TokenBindingStatusType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(TokenBindingStatusType, {
        {TokenBindingStatusType::Invalid, nullptr},
        {TokenBindingStatusType::Invalid, ""},
        {TokenBindingStatusType::Present, "present"},
        {TokenBindingStatusType::Supported, "supported"},
        {TokenBindingStatusType::NotSupported, "not-supported"}
    })

    struct TokenBindingType {

        TokenBindingType() noexcept = default;
        TokenBindingType(const json& j) :
            Status(j["status"].get<TokenBindingStatusType>()) {

            if (j.find("id") != j.end()) {
                ID.emplace(j["id"].get<std::string>());
            }
        }
        TokenBindingStatusType Status;
        std::optional<std::string> ID;
    };

    inline void to_json(json& j, const TokenBindingType& tokenBinding) {
        j = json{
            {"status", tokenBinding.Status}
        };

        if (tokenBinding.ID) {
            j["id"] = tokenBinding.ID.value();
        }
    }

    inline void from_json(const json& j, TokenBindingType& tokenBinding) {
        j.at("status").get_to(tokenBinding.Status);

        if (j.find("id") != j.end()) {
            tokenBinding.ID.emplace(j["id"].get<std::string>());
        }
    }

    // CollectedClientDataType represents the contextual bindings of both the WebAuthn Relying Party
    // and the client. It is a key-value mapping whose keys are strings. Values can be any type
    // that has a valid encoding in JSON. Its structure is defined by the following Web IDL.
    //
    // Specification: §5.8.1. Client Data Used in WebAuthn Signatures (https://www.w3.org/TR/webauthn/#dictdef-collectedclientdata)
    struct CollectedClientDataType {

        CollectedClientDataType() noexcept = default;
        CollectedClientDataType(const json& j) :
            Type(j["type"].get<CeremonyType>()),
            Challenge(j["challenge"].get<std::string>()),
            Origin(j["origin"].get<std::string>()) {

            if (j.find("tokenBinding") != j.end()) {
                TokenBinding.emplace(j["tokenBinding"].get<TokenBindingType>());
            }

            if (j.find("hint") != j.end()) {
                Hint.emplace(j["hint"].get<std::string>());
            }
        }

        // Verify handles steps 3 through 6 of verifying the registering client data of a
        // new credential and steps 7 through 10 of verifying an authentication assertion
        // See https://www.w3.org/TR/webauthn/#registering-a-new-credential
        // and https://www.w3.org/TR/webauthn/#verifying-assertion
        inline  std::optional<ErrorType> Verify(const std::string& storedChallenge, 
            CeremonyType ceremony, 
            const std::vector<std::string>& rpOrigins) noexcept {
            // Registration Step 3. Verify that the value of C.type is webauthn.create.

            // Assertion Step 7. Verify that the value of C.type is the string webauthn.get.
            /*if (Type != ceremony) {
                return ErrVerification.WithDetails("Error validating ceremony type").WithInfo(fmt::format("Expected Value: {}, Received: {}", ceremony, Type));
            }

            // Registration Step 4. Verify that the value of C.challenge matches the challenge
            // that was sent to the authenticator in the create() call.

            // Assertion Step 8. Verify that the value of C.challenge matches the challenge
            // that was sent to the authenticator in the PublicKeyCredentialRequestOptions
            // passed to the get() call.

            auto challenge = Challenge
            if (subtle.ConstantTimeCompare([]byte(storedChallenge), []byte(challenge)) != 1) {
                return ErrVerification.
                    WithDetails("Error validating challenge").
                    WithInfo(fmt.Sprintf("Expected b Value: %#v\nReceived b: %#v\n", storedChallenge, challenge))
            }

            // Registration Step 5 & Assertion Step 9. Verify that the value of C.origin matches
            // the Relying Party's origin.
            fqOrigin, err := FullyQualifiedOrigin(Origin)
            if (err) {
                return ErrParsingData.WithDetails("Error decoding clientData origin as URL")
            }

            auto found = false;

            for _, origin := range rpOrigins {
                if strings.EqualFold(fqOrigin, origin) {
                    found = true
                    break
                }
            }

            if (!found) {
                return ErrVerification.
                    WithDetails("Error validating origin").
                    WithInfo(fmt::format("Expected Values: {}, Received: {}", rpOrigins, fqOrigin));
            }

            // Registration Step 6 and Assertion Step 10. Verify that the value of C.tokenBinding.status
            // matches the state of Token Binding for the TLS connection over which the assertion was
            // obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id
            // matches the base64url encoding of the Token Binding ID for the connection.
            if (TokenBinding) {
                if (TokenBinding.value().Status == TokenBindingStatusType::Invalid) {
                    return ErrParsingData.WithDetails("Error decoding clientData, token binding present without status");
                }

                if (TokenBinding.value().Status != TokenBindingStatusType::Present && 
                    TokenBinding.value().Status != TokenBindingStatusType::Supported && 
                    TokenBinding.value().Status != TokenBindingStatusType::NotSupported) {
                    return ErrParsingData.
                        WithDetails("Error decoding clientData, token binding present with invalid status").
                        WithInfo(fmt::format("Got: {}", TokenBinding.value().Status));
                }
            }*/
            // Not yet fully implemented by the spec, browsers, and me.

            return std::nullopt;
        }

        // Type the string "webauthn.create" when creating new credentials,
        // and "webauthn.get" when getting an assertion from an existing credential. The
        // purpose of this member is to prevent certain types of signature confusion attacks
        // (where an attacker substitutes one legitimate signature for another).
        CeremonyType Type;
        std::string Challenge;
        std::string Origin;
        std::optional<TokenBindingType> TokenBinding; //*TokenBinding

        // Chromium (Chrome) returns a hint sometimes about how to handle clientDataJSON in a safe manner.
        std::optional<std::string> Hint;
    };

    inline void to_json(json& j, const CollectedClientDataType& collectedClientData) {
        j = json{
            {"type", collectedClientData.Type},
            {"challenge", collectedClientData.Challenge},
            {"origin", collectedClientData.Origin}
        };

        if (collectedClientData.TokenBinding) {
            j["tokenBinding"] = collectedClientData.TokenBinding.value();
        }

        if (collectedClientData.Hint) {
            j["hint"] = collectedClientData.Hint.value();
        }
    }

    inline void from_json(const json& j, CollectedClientDataType& collectedClientData) {
        j.at("type").get_to(collectedClientData.Type);
        j.at("challenge").get_to(collectedClientData.Challenge);
        j.at("origin").get_to(collectedClientData.Origin);

        if (j.find("tokenBinding") != j.end()) {
            collectedClientData.TokenBinding.emplace(j["tokenBinding"].get<TokenBindingType>());
        }

        if (j.find("hint") != j.end()) {
            collectedClientData.Hint.emplace(j["hint"].get<std::string>());
        }
    }

    // FullyQualifiedOrigin returns the origin per the HTML spec: (scheme)://(host)[:(port)].
    inline expected<std::string> FullyQualifiedOrigin(const std::string& rawOrigin) noexcept {
        /*if strings.HasPrefix(rawOrigin, "android:apk-key-hash:") {
            return rawOrigin, nil
        }

        var origin *url.URL

        if origin, err = url.ParseRequestURI(rawOrigin); err != nil {
            return "", err
        }

        if origin.Host == "" {
            return "", fmt::format("url '{}' does not have a host", rawOrigin);
        }

        origin.Path, origin.RawPath, origin.RawQuery, origin.User = "", "", "", nil

        return origin.String(), nil*/
    }

} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CLIENT_IPP */
