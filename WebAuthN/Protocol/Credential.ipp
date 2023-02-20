//
//  Credential.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CREDENTIAL_IPP
#define WEBAUTHN_PROTOCOL_CREDENTIAL_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "Base64.ipp"
#include "Core.ipp"
#include "Extensions.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    inline const std::string CREDENTIAL_TYPE_FIDO_U2F = "fido-u2f";

    using json = nlohmann::json;

    // CredentialType is the basic credential type from the Credential Management specification that is inherited by WebAuthn's
    // PublicKeyCredentialType type.
    //
    // Specification: Credential Management §2.2. The Credential Interface (https://www.w3.org/TR/credential-management/#credential)
    struct CredentialType {

        CredentialType() noexcept = default;
        CredentialType(const json& j) :
            ID(j["id"].get<std::string>()),
            Type(j["type"].get<std::string>()) {
        }

        // ID is The credential’s identifier. The requirements for the
	    // identifier are distinct for each type of credential. It might
	    // represent a username for username/password tuples, for example.
        std::string ID;

        // Type is the value of the object’s interface object's [[type]] slot,
	    // which specifies the credential type represented by this object.
	    // This should be type "public-key" for Webauthn credentials.
        std::string Type;
    };

    inline void to_json(json& j, const CredentialType& credential) {
        j = json{
            {"id", credential.ID},
            {"type", credential.Type}
        };
    }

    inline void from_json(const json& j, CredentialType& credential) {
        j.at("id").get_to(credential.ID);
        j.at("type").get_to(credential.Type);
    }

    // ParsedCredentialType is the parsed PublicKeyCredentialType interface, inherits from CredentialType, and contains
    // the attributes that are returned to the caller when a new credential is created, or a new assertion is requested.
    struct ParsedCredentialType {

        ParsedCredentialType() noexcept = default;
        ParsedCredentialType(const json& j) :
            ID(j["id"].get<std::string>()),
            Type(j["type"].get<std::string>()) {
        }
        ParsedCredentialType(const std::vector<std::uint8_t>& cbor) :
            ParsedCredentialType(json::from_cbor(cbor)) {
        }

        std::string ID;
        std::string Type;
    };

    inline void to_json(json& j, const ParsedCredentialType& parsedCredential) {
        j = json{
            {"id", parsedCredential.ID},
            {"type", parsedCredential.Type}
        };
    }

    inline void from_json(const json& j, ParsedCredentialType& parsedCredential) {
        j.at("id").get_to(parsedCredential.ID);
        j.at("type").get_to(parsedCredential.Type);
    }

    struct PublicKeyCredentialType : public CredentialType {

        PublicKeyCredentialType() noexcept = default;
        PublicKeyCredentialType(const json& j) :
            CredentialType(j),
            RawID(j["rawId"].get<URLEncodedBase64Type>()) {
            
            if (j.find("clientExtensionResults") != j.end()) {
                ClientExtensionResults.emplace(j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputsType>());
            }

            if (j.find("authenticatorAttachment") != j.end()) {
                AuthenticatorAttachment.emplace(["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
            }
        }

        URLEncodedBase64Type RawID;
        std::optional<AuthenticationExtensionsClientOutputsType> ClientExtensionResults;
        std::optional<AuthenticatorAttachmentType> AuthenticatorAttachment;
    };

    inline void to_json(json& j, const PublicKeyCredentialType& publicKeyCredential) {
        json _j;
        to_json(_j, static_cast<const CredentialType&>(publicKeyCredential));
        _j["rawId"] = publicKeyCredential.RawID;

        if (publicKeyCredential.ClientExtensionResults) {
            _j["clientExtensionResults"] = publicKeyCredential.ClientExtensionResults.value();
        }

        if (publicKeyCredential.AuthenticatorAttachment) {
            _j["authenticatorAttachment"] = publicKeyCredential.AuthenticatorAttachment.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, PublicKeyCredentialType& publicKeyCredential) {
        from_json(j, static_cast<CredentialType&>(publicKeyCredential));
        j.at("rawId").get_to(publicKeyCredential.RawID);

        if (j.find("clientExtensionResults") != j.end()) {
            publicKeyCredential.ClientExtensionResults.emplace(j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputsType>());
        }

        if (j.find("authenticatorAttachment") != j.end()) {
            publicKeyCredential.AuthenticatorAttachment.emplace(j["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
        }
    }

    struct ParsedPublicKeyCredentialType : public ParsedCredentialType {

        ParsedPublicKeyCredentialType() noexcept = default;
        ParsedPublicKeyCredentialType(const json& j) :
            ParsedCredentialType(j),
            RawID(j["rawId"].get<std::vector<uint8_t>>()) {
            
            if (j.find("clientExtensionResults") != j.end()) {
                ClientExtensionResults.emplace(j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputsType>());
            }

            if (j.find("authenticatorAttachment") != j.end()) {
                AuthenticatorAttachment.emplace(j["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
            }
        }

        ParsedPublicKeyCredentialType(const std::vector<std::uint8_t>& cbor) :
            ParsedPublicKeyCredentialType(json::from_cbor(cbor)) {
        }

        // GetAppID takes a AuthenticationExtensions object or nil. It then performs the following checks in order:
        //
        // 1. Check that the Session Data's AuthenticationExtensions has been provided and if it hasn't return an error.
        // 2. Check that the AuthenticationExtensionsClientOutputs contains the extensions output and return an empty string if it doesn't.
        // 3. Check that the Credential AttestationType is `fido-u2f` and return an empty string if it isn't.
        // 4. Check that the AuthenticationExtensionsClientOutputs contains the appid key and if it doesn't return an empty string.
        // 5. Check that the AuthenticationExtensionsClientOutputs appid is a bool and if it isn't return an error.
        // 6. Check that the appid output is true and if it isn't return an empty string.
        // 7. Check that the Session Data has an appid extension defined and if it doesn't return an error.
        // 8. Check that the appid extension in Session Data is a string and if it isn't return an error.
        // 9. Return the appid extension value from the Session data.
        inline expected<std::string> GetAppID(const AuthenticationExtensionsType& authExt, 
            const std::string& credentialAttestationType) const {
            return std::string("");
        }

        std::vector<uint8_t> RawID;
        std::optional<AuthenticationExtensionsClientOutputsType> ClientExtensionResults;
        std::optional<AuthenticatorAttachmentType> AuthenticatorAttachment;
    };

    inline void to_json(json& j, const ParsedPublicKeyCredentialType& parsedPublicKeyCredential) {
        json _j;
        to_json(_j, static_cast<const ParsedCredentialType&>(parsedPublicKeyCredential));
        _j["rawId"] = parsedPublicKeyCredential.RawID;

        if (parsedPublicKeyCredential.ClientExtensionResults) {
            _j["clientExtensionResults"] = parsedPublicKeyCredential.ClientExtensionResults.value();
        }

        if (parsedPublicKeyCredential.AuthenticatorAttachment) {
            _j["authenticatorAttachment"] = parsedPublicKeyCredential.AuthenticatorAttachment.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, ParsedPublicKeyCredentialType& parsedPublicKeyCredential) {
        from_json(j, static_cast<ParsedCredentialType&>(parsedPublicKeyCredential));
        j.at("rawId").get_to(parsedPublicKeyCredential.RawID);

        if (j.find("clientExtensionResults") != j.end()) {
            parsedPublicKeyCredential.ClientExtensionResults.emplace(j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputsType>());
        }

        if (j.find("authenticatorAttachment") != j.end()) {
            parsedPublicKeyCredential.AuthenticatorAttachment.emplace(j["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
        }
    }
    
    using TransportType = std::string;
    using TransportsType = std::vector<TransportType>;

    struct CredentialCreationResponseType : PublicKeyCredentialType {

        CredentialCreationResponseType() noexcept = default;
        CredentialCreationResponseType(const json& j) :
            PublicKeyCredentialType(j),
            AttestationResponse(j["response"].get<AuthenticatorAttestationResponseType>()) {
            
            if (j.find("transports") != j.end()) {
                Transports.emplace(j["transports"].get<TransportsType>());
            }
        }

        AuthenticatorAttestationResponseType AttestationResponse;
        std::optional<TransportsType> Transports;
    };

    inline void to_json(json& j, const CredentialCreationResponseType& credentialCreationResponse) {
        json _j;
        to_json(_j, static_cast<const PublicKeyCredentialType&>(credentialCreationResponse));
        _j["response"] = credentialCreationResponse.AttestationResponse;

        if (credentialCreationResponse.Transports) {
            _j["transports"] = credentialCreationResponse.Transports.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, CredentialCreationResponseType& credentialCreationResponse) {
        from_json(j, static_cast<PublicKeyCredentialType&>(credentialCreationResponse));
        j.at("response").get_to(credentialCreationResponse.AttestationResponse);

        if (j.find("transports") != j.end()) {
            credentialCreationResponse.Transports.emplace(j["transports"].get<TransportsType>());
        }
    }

    struct ParsedCredentialCreationDataType : ParsedPublicKeyCredentialType {

        ParsedCredentialCreationDataType() noexcept = default;
        ParsedCredentialCreationDataType(const json& j) :
            ParsedPublicKeyCredentialType(j) {
        }

        // Verify the Client and Attestation data.
        //
        // Specification: §7.1. Registering a New Credential (https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential)
        inline std::optional<ErrorType> Verify(const std::string& storedChallenge, 
            bool verifyUser, 
            const std::string& relyingPartyID, 
            const std::vector<std::string>& relyingPartyOrigins) const {

        }

        ParsedAttestationResponseType Response;
        CredentialCreationResponseType Raw;
    };

    inline void to_json(json& j, const ParsedCredentialCreationDataType& parsedCredentialCreationData) {
        to_json(j, static_cast<const ParsedPublicKeyCredentialType&>(parsedCredentialCreationData));
    }

    inline void from_json(const json& j, ParsedCredentialCreationDataType& parsedCredentialCreationData) {
        from_json(j, static_cast<ParsedPublicKeyCredentialType&>(parsedCredentialCreationData));
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CREDENTIAL_IPP */
