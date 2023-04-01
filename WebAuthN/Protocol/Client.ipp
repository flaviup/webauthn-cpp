//
//  Client.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CLIENT_IPP
#define WEBAUTHN_PROTOCOL_CLIENT_IPP

#include <vector>
#include "Authenticator.ipp"
#include "../Util/UrlParse.ipp"
#include "../Util/StringCompare.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Enums

    enum class CeremonyType {
        Create,
        Assert,
        Invalid = -1 // Invalid value
    };

    // map CeremonyType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(CeremonyType, {
        { CeremonyType::Invalid,          nullptr },
        { CeremonyType::Invalid,               "" },
        { CeremonyType::Create, "webauthn.create" },
        { CeremonyType::Assert,    "webauthn.get" }
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
        { TokenBindingStatusType::Invalid,              nullptr },
        { TokenBindingStatusType::Invalid,                   "" },
        { TokenBindingStatusType::Present,            "present" },
        { TokenBindingStatusType::Supported,        "supported" },
        { TokenBindingStatusType::NotSupported, "not-supported" }
    })

    // Structs

    struct TokenBindingType {

        TokenBindingType() noexcept = default;

        TokenBindingType(const json& j) :
            Status(j["status"].get<TokenBindingStatusType>()) {

            if (j.find("id") != j.end()) {
                ID.emplace(j["id"].get<std::string>());
            }
        }

        TokenBindingType(const TokenBindingType& tokenBinding) noexcept = default;
        TokenBindingType(TokenBindingType&& tokenBinding) noexcept = default;
        ~TokenBindingType() noexcept = default;

        TokenBindingType& operator =(const TokenBindingType& other) noexcept = default;
        TokenBindingType& operator =(TokenBindingType&& other) noexcept = default;

        TokenBindingStatusType Status;
        std::optional<std::string> ID;
    };

    inline void to_json(json& j, const TokenBindingType& tokenBinding) {

        j = json{
            { "status", tokenBinding.Status }
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

            if (j.find("crossOrigin") != j.end()) {
                CrossOrigin.emplace(j["crossOrigin"].get<bool>());
            }

            if (j.find("tokenBinding") != j.end()) {
                TokenBinding.emplace(j["tokenBinding"].get<TokenBindingType>());
            }

            if (j.find("hint") != j.end()) {
                Hint.emplace(j["hint"].get<std::string>());
            }
        }

        CollectedClientDataType(const CollectedClientDataType& collectedClientData) noexcept = default;
        CollectedClientDataType(CollectedClientDataType&& collectedClientData) noexcept = default;
        ~CollectedClientDataType() noexcept = default;

        CollectedClientDataType& operator =(const CollectedClientDataType& other) noexcept = default;
        CollectedClientDataType& operator =(CollectedClientDataType&& other) noexcept = default;

        // Verify handles steps 3 through 6 of verifying the registering client data of a
        // new credential and steps 7 through 10 of verifying an authentication assertion
        // See https://www.w3.org/TR/webauthn/#registering-a-new-credential
        // and https://www.w3.org/TR/webauthn/#verifying-assertion
        inline  std::optional<ErrorType>
        Verify(const std::string& storedChallenge, 
               CeremonyType ceremony, 
               const std::vector<std::string>& rpOrigins) const noexcept {

            // Registration Step 3. Verify that the value of Type is webauthn.create.

            // Assertion Step 7. Verify that the value of Type is the string webauthn.get.
            if (Type != ceremony) {
                return ErrVerification().WithDetails("Error validating ceremony type")
                                        .WithInfo(fmt::format("Expected Value: {}, Received: {}",
                                                              json(ceremony).get<std::string>(),
                                                              json(Type).get<std::string>()));
            }

            // Registration Step 4. Verify that the value of Challenge matches the challenge
            // that was sent to the authenticator in the create() call.

            // Assertion Step 8. Verify that the value of Challenge matches the challenge
            // that was sent to the authenticator in the PublicKeyCredentialRequestOptions
            // passed to the get() call.

            if (!Util::StringCompare::ConstantTimeEqual(storedChallenge, Challenge)) {
                return ErrVerification().WithDetails("Error validating challenge")
                                        .WithInfo(fmt::format("Expected b Value: {}\nReceived b: {}\n", storedChallenge, Challenge));
            }

            // Registration Step 5 & Assertion Step 9. Verify that the value of C.origin matches
            // the Relying Party's origin.
            std::string fqOrigin{};
            auto ok = Util::Url::FullyQualifiedOrigin(Origin, fqOrigin);

            if (!ok) {
                return ErrParsingData().WithDetails("Error decoding clientData origin as URL");
            }
            auto found = std::any_of(rpOrigins.cbegin(), 
                                     rpOrigins.cend(), 
                                     [&fqOrigin](const std::string& origin) { return Util::StringCompare::Utf8EqualFold(fqOrigin, origin); });

            if (!found) {
                return ErrVerification().WithDetails("Error validating origin")
                                        .WithInfo(fmt::format("Expected Values: {}, Received: {}",
                                                              fmt::join(rpOrigins, ", "),
                                                              fqOrigin));
            }

            // Registration Step 6 and Assertion Step 10. Verify that the value of C.tokenBinding.status
            // matches the state of Token Binding for the TLS connection over which the assertion was
            // obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id
            // matches the base64url encoding of the Token Binding ID for the connection.
            if (TokenBinding) {

                if (TokenBinding.value().Status == TokenBindingStatusType::Invalid) {
                    return ErrParsingData().WithDetails("Error decoding clientData, token binding present without status");
                }

                if (TokenBinding.value().Status != TokenBindingStatusType::Present && 
                    TokenBinding.value().Status != TokenBindingStatusType::Supported && 
                    TokenBinding.value().Status != TokenBindingStatusType::NotSupported) {

                    return ErrParsingData().WithDetails("Error decoding clientData, token binding present with invalid status")
                                           .WithInfo(fmt::format("Got: {}",
                                                                 json(TokenBinding.value().Status).get<std::string>()));
                }
            }

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
        std::optional<bool> CrossOrigin;
        std::optional<TokenBindingType> TokenBinding; //*TokenBinding

        // Chromium (Chrome) returns a hint sometimes about how to handle clientDataJSON in a safe manner.
        std::optional<std::string> Hint;
    };

    inline void to_json(json& j, const CollectedClientDataType& collectedClientData) {

        j = json{
            { "type",           collectedClientData.Type },
            { "challenge", collectedClientData.Challenge },
            { "origin",       collectedClientData.Origin }
        };
        
        if (collectedClientData.CrossOrigin) {
            j["crossOrigin"] = collectedClientData.CrossOrigin.value();
        }

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
        
        if (j.find("crossOrigin") != j.end()) {
            collectedClientData.CrossOrigin.emplace(j["crossOrigin"].get<bool>());
        }

        if (j.find("tokenBinding") != j.end()) {
            collectedClientData.TokenBinding.emplace(j["tokenBinding"].get<TokenBindingType>());
        }

        if (j.find("hint") != j.end()) {
            collectedClientData.Hint.emplace(j["hint"].get<std::string>());
        }
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CLIENT_IPP */
