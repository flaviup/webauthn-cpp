//
//  Attestation.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_IPP

#include <any>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <tuple>
#include <utility>
#include <nlohmann/json.hpp>
#include "Client.ipp"
#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // AttestationObjectType is the raw attestationObject.
    //
    // Authenticators SHOULD also provide some form of attestation, if possible. If an authenticator does, the basic
    // requirement is that the authenticator can produce, for each credential public key, an attestation statement
    // verifiable by the WebAuthn Relying Party. Typically, this attestation statement contains a signature by an
    // attestation private key over the attested credential public key and a challenge, as well as a certificate or similar
    // data providing provenance information for the attestation public key, enabling the Relying Party to make a trust
    // decision. However, if an attestation key pair is not available, then the authenticator MAY either perform self
    // attestation of the credential public key with the corresponding credential private key, or otherwise perform no
    // attestation. All this information is returned by authenticators any time a new public key credential is generated, in
    // the overall form of an attestation object.
    //
    // Specification: §6.5. Attestation (https://www.w3.org/TR/webauthn/#sctn-attestation)
    struct AttestationObjectType {

        AttestationObjectType() noexcept = default;
        AttestationObjectType(const json& j) :
            RawAuthData(j["authData"].get<std::vector<uint8_t>>()),
            Format(j["fmt"].get<std::string>()) {

            if (j.find("attStmt") != j.end()) {
                AttStatement.emplace(j["attStmt"].get<std::map<std::string, std::any>>());
            }
        }

        // Verify performs Steps 9 through 14 of registration verification.
        //
        // Steps 9 through 12 are verified against the auth data. These steps are identical to 11 through 14 for assertion so we
        // handle them with AuthData.
        inline std::optional<ErrorType> Verify(const std::string& relyingPartyID, 
            const std::vector<uint8_t>& clientDataHash, 
            bool verificationRequired) const {
        }

        // The authenticator data, including the newly created public key. See AuthenticatorData for more info
        AuthenticatorDataType AuthData;
        // The byteform version of the authenticator data, used in part for signature validation
        std::vector<uint8_t> RawAuthData;
        // The format of the Attestation data.
        std::string Format;
        // The attestation statement data sent back if attestation is requested.
        std::optional<std::map<std::string, std::any>> AttStatement;
    };

    inline void to_json(json& j, const AttestationObjectType& attestationObject) {

        j = json{
            {"authData", attestationObject.RawAuthData},
            {"fmt", attestationObject.Format}
        };

        if (attestationObject.AttStatement) {
            j["attStmt"] = attestationObject.AttStatement.value();
        }
    }

    inline void from_json(const json& j, AttestationObjectType& attestationObject) {

        j.at("authData").get_to(attestationObject.RawAuthData);
        j.at("fmt").get_to(attestationObject.Format);

        if (j.find("attStmt") != j.end()) {
            attestationObject.AttStatement.emplace(j["attStmt"].get<std::map<std::string, std::any>>());
        }
    }

    // ParsedAttestationResponseType is the parsed version of AuthenticatorAttestationResponseType.
    struct ParsedAttestationResponseType {
        
        ParsedAttestationResponseType() noexcept = default;

        CollectedClientDataType CollectedClientData;
        AttestationObjectType AttestationObject;
        std::vector<AuthenticatorTransportType> Transports;
    };

    // AuthenticatorAttestationResponseType is the initial unpacked 'response' object received by the relying party. This
    // contains the clientDataJSON object, which will be marshalled into CollectedClientDataType, and the 'attestationObject',
    // which contains information about the authenticator, and the newly minted public key credential. The information in
    // both objects are used to verify the authenticity of the ceremony and new credential.
    //
    // See: https://www.w3.org/TR/webauthn/#typedefdef-publickeycredentialjson
    struct AuthenticatorAttestationResponseType : public AuthenticatorResponseType {

        AuthenticatorAttestationResponseType() noexcept = default;
        AuthenticatorAttestationResponseType(const json& j) :
            AuthenticatorResponseType(j), // // The byte slice of clientDataJSON, which becomes CollectedClientData
            AttestationObject(j["attestationObject"].get<URLEncodedBase64Type>()) {
            
            if (j.find("transports") != j.end()) {
                Transports.emplace(j["transports"].get<std::vector<std::string>>());
            }
        }

        // Parse the values returned in the authenticator response and perform attestation verification
        // Step 8. This returns a fully decoded struct with the data put into a format that can be
        // used to verify the user and credential that was created.
        inline expected<ParsedAttestationResponseType> Parse() const {
        }

        // AttestationObject is the byte slice version of attestationObject.
        // This attribute contains an attestation object, which is opaque to, and
        // cryptographically protected against tampering by, the client. The
        // attestation object contains both authenticator data and an attestation
        // statement. The former contains the AAGUID, a unique credential ID, and
        // the credential public key. The contents of the attestation statement are
        // determined by the attestation statement format used by the authenticator.
        // It also contains any additional information that the Relying Party's server
        // requires to validate the attestation statement, as well as to decode and
        // validate the authenticator data along with the JSON-serialized client data.
        URLEncodedBase64Type AttestationObject;
        std::optional<std::vector<std::string>> Transports;
    };

    inline void to_json(json& j, const AuthenticatorAttestationResponseType& authenticatorAttestationResponse) {

        json _j;
        to_json(_j, static_cast<const AuthenticatorResponseType&>(authenticatorAttestationResponse));
        _j["attestationObject"] = authenticatorAttestationResponse.AttestationObject;

        if (authenticatorAttestationResponse.Transports) {
            _j["transports"] = authenticatorAttestationResponse.Transports.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, AuthenticatorAttestationResponseType& authenticatorAttestationResponse) {

        from_json(j, static_cast<AuthenticatorResponseType&>(authenticatorAttestationResponse));
        j.at("attestationObject").get_to(authenticatorAttestationResponse.AttestationObject);

        if (j.find("transports") != j.end()) {
            authenticatorAttestationResponse.Transports.emplace(j["transports"].get<std::vector<std::string>>());
        }
    }

    using AttestationFormatValidationHandlerType = expected<std::pair<std::string, std::any>> (*)(const AttestationObjectType& attestationObject, const std::vector<uint8_t>& data);

    inline std::map<std::string, AttestationFormatValidationHandlerType> ATTESTATION_REGISTRY{};

    // RegisterAttestationFormat is a method to register attestation formats with the library. Generally using one of the
    // locally registered attestation formats is sufficient.
    inline void RegisterAttestationFormat(const std::string& format, AttestationFormatValidationHandlerType handler) {

	    ATTESTATION_REGISTRY[format] = handler;
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_IPP