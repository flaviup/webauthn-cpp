//
//  Attestation.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_IPP

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <tuple>
#include <utility>
#include <nlohmann/json.hpp>
#include <uuid/uuid.h>
#include "Client.ipp"
#include "../Util/Crypto.ipp"
#include "../Metadata/Metadata.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Attestation Registry

    using AttestationFormatValidationHandlerType = expected<std::tuple<std::string, std::optional<json>>> (*)(const struct AttestationObjectType& attestationObject, const std::vector<uint8_t>& data);
    inline std::map<std::string, AttestationFormatValidationHandlerType> ATTESTATION_REGISTRY{};

    // RegisterAttestationFormat is a function to register attestation formats with the library. Generally using one of the
    // locally registered attestation formats is sufficient.
    inline void RegisterAttestationFormat(const std::string& format, AttestationFormatValidationHandlerType handler) {

        ATTESTATION_REGISTRY[format] = handler;
    }

    // Structs

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
            RawAuthData(j["authData"].get_binary()),
            Format(j["fmt"].get<std::string>()) {

            if (j.find("attStmt") != j.end()) {
                AttStatement.emplace(j["attStmt"].get<json>());
            }
        }

        AttestationObjectType(const AttestationObjectType& attestationObject) noexcept = default;
        AttestationObjectType(AttestationObjectType&& attestationObject) noexcept = default;
        ~AttestationObjectType() noexcept = default;

        AttestationObjectType& operator =(const AttestationObjectType& other) noexcept = default;
        AttestationObjectType& operator =(AttestationObjectType&& other) noexcept = default;

        // Verify performs Steps 9 through 14 of registration verification.
        //
        // Steps 9 through 12 are verified against the auth data. These steps are identical to 11 through 14 for assertion so we
        // handle them with AuthData.
        inline std::optional<ErrorType>
        Verify(const std::string& relyingPartyID, 
               const std::vector<uint8_t>& clientDataHash, 
               bool verificationRequired) const noexcept {

            auto rpIDHash = Util::Crypto::SHA256(relyingPartyID);

            // Begin Step 9 through 12. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the RP.
            auto err = AuthData.Verify(rpIDHash, std::vector<uint8_t>{}, verificationRequired);

            if (err) {
                return err;
            }

            // Step 13. Determine the attestation statement format by performing a
            // USASCII case-sensitive match on fmt against the set of supported
            // WebAuthn Attestation Statement Format Identifier values. The up-to-date
            // list of registered WebAuthn Attestation Statement Format Identifier
            // values is maintained in the IANA registry of the same name
            // [WebAuthn-Registries] (https://www.w3.org/TR/webauthn/#biblio-webauthn-registries).

            // Since there is not an active registry yet, we'll check it against our internal
            // Supported types.

            // But first let's make sure attestation is present. If it isn't, we don't need to handle
            // any of the following steps
            if (Format == "none") {

                if (AttStatement && !AttStatement.value().empty()) {
                    return ErrAttestationFormat().WithInfo("Attestation format none with attestation present");
                }

                return std::nullopt;
            }
            auto formatHandlerIter = ATTESTATION_REGISTRY.find(Format);
            
            if (formatHandlerIter == ATTESTATION_REGISTRY.cend()) {
                return ErrAttestationFormat().WithInfo(fmt::format("Attestation format {} is unsupported", Format));
            }

            // Step 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using
            // the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized
            // client data computed in step 7.
            auto formatHandler = formatHandlerIter->second;
            auto result = formatHandler(*this, clientDataHash);

            if (!result) {
                return result.error();
            }
            auto [attestationType, x5c] = result.value();

            uuid_t aaguid;
            auto aaguidSize = std::min(AuthData.AttData.AAGUID.size(), sizeof(aaguid));
            std::memcpy(aaguid, AuthData.AttData.AAGUID.data(), aaguidSize);
            auto metaIter = Metadata::METADATA.find(aaguid);

            if (metaIter != Metadata::METADATA.cend()) {

                auto meta = metaIter->second;

                for (const auto& s : meta.StatusReports) {
                    
                    if (Metadata::IsUndesiredAuthenticatorStatus(s.Status)) {
                        return ErrInvalidAttestation().WithDetails("Authenticator with undesirable status encountered");
                    }
                }

                if (x5c && !x5c.value().empty()) {

                    auto namesResult = Util::Crypto::GetNamesX509(x5c.value()[0]);
                    
                    if (!namesResult) {
                        return ErrInvalidAttestation().WithDetails("Unable to parse attestation certificate from x5c");
                    }
                    auto [subjectName, issuerName] = namesResult.value();

                    if (subjectName != issuerName) {

                        auto hasBasicFull = false;

                        if (meta.MetadataStatement) {

                            for (const auto& a : meta.MetadataStatement.value().AttestationTypes) {
                                
                                if (a == Metadata::AuthenticatorAttestationType::BasicFull) {
                                    hasBasicFull = true;
                                }
                            }
                        }

                        if (!hasBasicFull) {
                            return ErrInvalidAttestation().WithDetails("Attestation with full attestation from authenticator that does not support full attestation");
                        }
                    }
                }
            } else if (Metadata::Conformance) {

                char strAaguid[37]{0};
                uuid_unparse(aaguid, strAaguid);
                return ErrInvalidAttestation().WithDetails(fmt::format("AAGUID {} not found in metadata during conformance testing", strAaguid));
            }

            return std::nullopt;
        }

        // The authenticator data, including the newly created public key. See AuthenticatorData for more info
        AuthenticatorDataType AuthData;
        // The byteform version of the authenticator data, used in part for signature validation
        std::vector<uint8_t> RawAuthData;
        // The format of the Attestation data.
        std::string Format;
        // The attestation statement data sent back if attestation is requested.
        std::optional<json> AttStatement;
    };

    inline void to_json(json& j, const AttestationObjectType& attestationObject) {

        j = json{
            { "authData", attestationObject.RawAuthData },
            { "fmt",           attestationObject.Format }
        };

        if (attestationObject.AttStatement) {
            j["attStmt"] = attestationObject.AttStatement.value();
        }
    }

    inline void from_json(const json& j, AttestationObjectType& attestationObject) {

        attestationObject.RawAuthData = j.at("authData").get_binary();
        j.at("fmt").get_to(attestationObject.Format);

        if (j.find("attStmt") != j.end()) {
            attestationObject.AttStatement.emplace(j["attStmt"].get<json>());
        }
    }

    // ParsedAttestationResponseType is the parsed version of AuthenticatorAttestationResponseType.
    struct ParsedAttestationResponseType {
        
        ParsedAttestationResponseType() noexcept = default;
        
        ParsedAttestationResponseType(const CollectedClientDataType& collectedClientData,
            const AttestationObjectType& attestationObject,
            const std::vector<AuthenticatorTransportType>& transports) noexcept : 
            CollectedClientData(collectedClientData), 
            AttestationObject(attestationObject), 
            Transports(transports) {
        }

        ParsedAttestationResponseType(const ParsedAttestationResponseType& parsedAttestationResponse) noexcept = default;
        ParsedAttestationResponseType(ParsedAttestationResponseType&& parsedAttestationResponse) noexcept = default;
        ~ParsedAttestationResponseType() noexcept = default;

        ParsedAttestationResponseType& operator =(const ParsedAttestationResponseType& other) noexcept = default;
        ParsedAttestationResponseType& operator =(ParsedAttestationResponseType&& other) noexcept = default;

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

        AuthenticatorAttestationResponseType(const AuthenticatorAttestationResponseType& authenticatorAttestationResponse) noexcept = default;
        AuthenticatorAttestationResponseType(AuthenticatorAttestationResponseType&& authenticatorAttestationResponse) noexcept = default;
        ~AuthenticatorAttestationResponseType() noexcept override = default;

        AuthenticatorAttestationResponseType& operator =(const AuthenticatorAttestationResponseType& other) noexcept = default;
        AuthenticatorAttestationResponseType& operator =(AuthenticatorAttestationResponseType&& other) noexcept = default;

        // Parse the values returned in the authenticator response and perform attestation verification
        // Step 8. This returns a fully decoded struct with the data put into a format that can be
        // used to verify the user and credential that was created.
        inline expected<ParsedAttestationResponseType> Parse() const noexcept {

            auto decodedClientData = URLEncodedBase64_Decode(ClientDataJSON);

            if (!decodedClientData) {
                return unexpected(ErrParsingData().WithDetails("Error unmarshalling client data json"));
            }
            auto collectedClientData = decodedClientData.value(); //WebAuthNCBOR::JsonUnmarshal(decodedClientData.value());
            auto decodedAttestationData = URLEncodedBase64_DecodeAsBinary(AttestationObject);

            if (!decodedAttestationData) {
                return unexpected(ErrParsingData().WithDetails("Error unmarshalling attestation data"));
            }
            auto attestationData = WebAuthNCBOR::JsonUnmarshal(decodedAttestationData.value());

            if (!attestationData) {
                return unexpected(attestationData.error());
            }
            auto attestationObject = attestationData.value().get<AttestationObjectType>();

            // Step 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
            // structure to obtain the attestation statement format fmt, the authenticator data authData, and
            // the attestation statement attStmt.
            auto err = attestationObject.AuthData.Unmarshal(attestationObject.RawAuthData);

            if (err) {
                return unexpected(fmt::format("error decoding auth data: {}", std::string(err.value())));
            }

            if (!HasAttestedCredentialData(attestationObject.AuthData.Flags)) {
                return unexpected(ErrAttestationFormat().WithInfo("Attestation missing attested credential data flag"));
            }

            std::vector<AuthenticatorTransportType> transports{};

            if (Transports) {

                for (const auto& t : Transports.value()) {

                    auto authT = json(t).get<AuthenticatorTransportType>();
                    transports.push_back(authT);
                }
            }

            return ParsedAttestationResponseType{
                json::parse(collectedClientData).get<CollectedClientDataType>(),
                attestationObject,
                transports
            };
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
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_IPP
