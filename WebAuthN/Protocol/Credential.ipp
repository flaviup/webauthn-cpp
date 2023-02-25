//
//  Credential.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CREDENTIAL_IPP
#define WEBAUTHN_PROTOCOL_CREDENTIAL_IPP

#include "Core.ipp"
#include "Attestation.ipp"
#include "Client.ipp"
#include "../Util/Crypto.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Consts

    inline const std::string CREDENTIAL_TYPE_FIDO_U2F = "fido-u2f";

    // Structs

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

        CredentialType(const CredentialType& credential) noexcept = default;
        CredentialType(CredentialType&& credential) noexcept = default;
        virtual ~CredentialType() noexcept = default;

        CredentialType& operator =(const CredentialType& other) noexcept = default;
        CredentialType& operator =(CredentialType&& other) noexcept = default;

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
            { "id",     credential.ID },
            { "type", credential.Type }
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

        ParsedCredentialType(const std::string& id,
            const std::string& type) noexcept : 
            ID(id), 
            Type(type) {
        }

        ParsedCredentialType(const json& j) :
            ID(j["id"].get<std::string>()),
            Type(j["type"].get<std::string>()) {
        }

        ParsedCredentialType(const std::vector<std::uint8_t>& cbor) :
            ParsedCredentialType(json::from_cbor(cbor)) {
        }

        ParsedCredentialType(const ParsedCredentialType& parsedCredential) noexcept = default;
        ParsedCredentialType(ParsedCredentialType&& parsedCredential) noexcept = default;
        virtual ~ParsedCredentialType() noexcept = default;

        ParsedCredentialType& operator =(const ParsedCredentialType& other) noexcept = default;
        ParsedCredentialType& operator =(ParsedCredentialType&& other) noexcept = default;

        std::string ID;
        std::string Type;
    };

    inline void to_json(json& j, const ParsedCredentialType& parsedCredential) {

        j = json{
            { "id",     parsedCredential.ID },
            { "type", parsedCredential.Type }
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

        PublicKeyCredentialType(const PublicKeyCredentialType& publicKeyCredential) noexcept = default;
        PublicKeyCredentialType(PublicKeyCredentialType&& publicKeyCredential) noexcept = default;
        virtual ~PublicKeyCredentialType() noexcept override = default;

        PublicKeyCredentialType& operator =(const PublicKeyCredentialType& other) noexcept = default;
        PublicKeyCredentialType& operator =(PublicKeyCredentialType&& other) noexcept = default;

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

        ParsedPublicKeyCredentialType(const ParsedCredentialType& pc,
            const std::vector<uint8_t>& rawID,
            const std::optional<AuthenticationExtensionsClientOutputsType>& clientExtensionResults = std::nullopt,
            const std::optional<AuthenticatorAttachmentType>& authenticatorAttachment = std::nullopt) noexcept :
            ParsedCredentialType(pc),
            RawID(rawID),
            ClientExtensionResults(clientExtensionResults), 
            AuthenticatorAttachment(authenticatorAttachment) {
        }

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

        ParsedPublicKeyCredentialType(const ParsedPublicKeyCredentialType& parsedPublicKeyCredential) noexcept = default;
        ParsedPublicKeyCredentialType(ParsedPublicKeyCredentialType&& parsedPublicKeyCredential) noexcept = default;
        virtual ~ParsedPublicKeyCredentialType() noexcept override = default;

        ParsedPublicKeyCredentialType& operator =(const ParsedPublicKeyCredentialType& other) noexcept = default;
        ParsedPublicKeyCredentialType& operator =(ParsedPublicKeyCredentialType&& other) noexcept = default;

        // GetAppID takes a AuthenticationExtensions object. It then performs the following checks in order:
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
        inline expected<std::string>
        GetAppID(const std::optional<AuthenticationExtensionsType>& authExt, 
                 const std::string& credentialAttestationType) const noexcept {

            bool enableAppID = false;

            if (!authExt || authExt.value().empty() || !ClientExtensionResults || ClientExtensionResults.value().empty()) {
                return "";
            }

            // If the credential does not have the correct attestation type it is assumed to NOT be a fido-u2f credential.
            // https://www.w3.org/TR/webauthn/#sctn-fido-u2f-attestation
            if (credentialAttestationType != CREDENTIAL_TYPE_FIDO_U2F) {
                return "";
            }
            auto itCer = ClientExtensionResults.value().find(EXTENSION_APPID);

            if (itCer == ClientExtensionResults.value().end()) {
                return "";
            }

            try {
                enableAppID = (itCer->second).get<bool>();
            } catch(const std::exception& e) {
                return unexpected(ErrBadRequest().WithDetails("Client Output appid did not have the expected type"));
            }

            if (!enableAppID) {
                return "";
            }
            auto it = authExt.value().find(EXTENSION_APPID);

            if (it == authExt.value().end() || it->second.empty()) {
                return unexpected(ErrBadRequest().WithDetails("Session Data does not have an appid but Client Output indicates it should be set"));
            }

            try {
                return (it->second).get<std::string>();
            } catch(const std::exception& e) {
                return unexpected(ErrBadRequest().WithDetails("Session Data appid did not have the expected type"));
            }
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

    struct CredentialCreationResponseType : public PublicKeyCredentialType {

        CredentialCreationResponseType() noexcept = default;

        CredentialCreationResponseType(const json& j) :
            PublicKeyCredentialType(j),
            AttestationResponse(j["response"].get<AuthenticatorAttestationResponseType>()) {
            
            if (j.find("transports") != j.end()) {
                Transports.emplace(j["transports"].get<std::vector<std::string>>());
            }
        }

        CredentialCreationResponseType(const CredentialCreationResponseType& credentialCreationResponse) noexcept = default;
        CredentialCreationResponseType(CredentialCreationResponseType&& credentialCreationResponse) noexcept = default;
        ~CredentialCreationResponseType() noexcept override = default;

        CredentialCreationResponseType& operator =(const CredentialCreationResponseType& other) noexcept = default;
        CredentialCreationResponseType& operator =(CredentialCreationResponseType&& other) noexcept = default;

        AuthenticatorAttestationResponseType AttestationResponse;
        std::optional<std::vector<std::string>> Transports;
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
            credentialCreationResponse.Transports.emplace(j["transports"].get<std::vector<std::string>>());
        }
    }

    struct ParsedCredentialCreationDataType : public ParsedPublicKeyCredentialType {

        ParsedCredentialCreationDataType() noexcept = default;

        ParsedCredentialCreationDataType(const ParsedPublicKeyCredentialType& ppkc,
            const ParsedAttestationResponseType& response,
            const CredentialCreationResponseType& raw) noexcept : 
            ParsedPublicKeyCredentialType(ppkc),
            Response(response),
            Raw(raw) {
        }

        ParsedCredentialCreationDataType(const json& j) :
            ParsedPublicKeyCredentialType(j) {
        }

        ParsedCredentialCreationDataType(const ParsedCredentialCreationDataType& parsedCredentialCreationData) noexcept = default;
        ParsedCredentialCreationDataType(ParsedCredentialCreationDataType&& parsedCredentialCreationData) noexcept = default;
        ~ParsedCredentialCreationDataType() noexcept override = default;

        ParsedCredentialCreationDataType& operator =(const ParsedCredentialCreationDataType& other) noexcept = default;
        ParsedCredentialCreationDataType& operator =(ParsedCredentialCreationDataType&& other) noexcept = default;

        // Parse validates and parses the CredentialCreationResponseType into a ParsedCredentialCreationDataType.
        inline static expected<ParsedCredentialCreationDataType> Parse(const CredentialCreationResponseType& credentialCreationResponse) noexcept {

            if (credentialCreationResponse.ID.empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Registration").WithInfo("Missing ID"));
            }
            auto testB64Result = URLEncodedBase64_Decode(credentialCreationResponse.ID);

            if (!testB64Result || testB64Result.value().empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Registration").WithInfo("ID not base64 URL Encoded"));
            }

            if (credentialCreationResponse.Type.empty()) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Registration").WithInfo("Missing type"));
            }

            if (json(credentialCreationResponse.Type).get<CredentialTypeType>() != CredentialTypeType::PublicKey) {
                return unexpected(ErrBadRequest().WithDetails("Parse error for Registration").WithInfo(fmt::format("Type not {}", json(CredentialTypeType::PublicKey))));
            }

            auto responseParseResult = credentialCreationResponse.AttestationResponse.Parse();
            
            if (!responseParseResult) {
                return unexpected(ErrParsingData().WithDetails("Error parsing attestation response"));
            }
            auto response = responseParseResult.value();

            // TODO: Remove this as it's a backwards compatibility layer.
            if (response.Transports.empty() && credentialCreationResponse.Transports && !credentialCreationResponse.Transports.value().empty()) {

                for (const auto& t : credentialCreationResponse.Transports.value()) {

                    auto authT = json(t).get<AuthenticatorTransportType>();

                    if (authT == AuthenticatorTransportType::Invalid) {
                        return unexpected(ErrParsingData().WithDetails("Error parsing authenticator transport type " + t));
                    }
                    response.Transports.push_back(authT);
                }
            }
            auto attachment = json(credentialCreationResponse.AuthenticatorAttachment.value()).get<AuthenticatorAttachmentType>();

            return ParsedCredentialCreationDataType{
                ParsedPublicKeyCredentialType{
                    ParsedCredentialType{
                        credentialCreationResponse.ID, 
                        credentialCreationResponse.Type
                    },
                    std::vector<uint8_t>(credentialCreationResponse.RawID.begin(), credentialCreationResponse.RawID.end()),
                    credentialCreationResponse.ClientExtensionResults,
                    std::optional<AuthenticatorAttachmentType>(attachment)
                },
                response,
                credentialCreationResponse
            };
        }

        // Verify the Client and Attestation data.
        //
        // Specification: §7.1. Registering a New Credential (https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential)
        inline std::optional<ErrorType>
        Verify(const std::string& storedChallenge,
               bool verifyUser,
               const std::string& relyingPartyID,
               const std::vector<std::string>& relyingPartyOrigins) const noexcept {

            // Handles steps 3 through 6 - Verifying the Client Data against the Relying Party's stored data
            auto err = Response.CollectedClientData.Verify(storedChallenge, CeremonyType::Create, relyingPartyOrigins);

            if (err) {
                return err;
            }

            // Step 7. Compute the hash of response.clientDataJSON using SHA-256.
            auto clientDataHash = Util::Crypto::SHA256(Raw.AttestationResponse.ClientDataJSON);

            // Step 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
            // structure to obtain the attestation statement format fmt, the authenticator data authData, and the
            // attestation statement attStmt.

            // We do the above step while parsing and decoding the CredentialCreationResponse
            // Handle steps 9 through 14 - This verifies the attestation object.
            err = Response.AttestationObject.Verify(relyingPartyID, clientDataHash, verifyUser);

            if (err) {
                return err;
            }

            // Step 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root
            // certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement
            // format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service provides
            // one way to obtain such information, using the AAGUID in the attestedCredentialData in authData.
            // [https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html]

            // TODO: There are no valid AAGUIDs yet or trust sources supported. We could implement policy for the RP in
            // the future, however.

            // Step 16. Assess the attestation trustworthiness using outputs of the verification procedure in step 14, as follows:
            // - If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            // - If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in
            //   the set of acceptable trust anchors obtained in step 15.
            // - Otherwise, use the X.509 certificates returned by the verification procedure to verify that the
            //   attestation public key correctly chains up to an acceptable root certificate.

            // TODO: We're not supporting trust anchors, self-attestation policy, or acceptable root certs yet.

            // Step 17. Check that the credentialId is not yet registered to any other user. If registration is
            // requested for a credential that is already registered to a different user, the Relying Party SHOULD
            // fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting
            // the older registration.

            // TODO: We can't support this in the code's current form, the Relying Party would need to check for this
            // against their database.

            // Step 18 If the attestation statement attStmt verified successfully and is found to be trustworthy, then
            // register the new credential with the account that was denoted in the options.user passed to create(), by
            // associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as
            // appropriate for the Relying Party's system.

            // Step 19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above,
            // the Relying Party SHOULD fail the registration ceremony.

            // TODO: Not implemented for the reasons mentioned under Step 16

            return std::nullopt;
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

    // Functions

    inline expected<ParsedCredentialCreationDataType> ParseCredentialCreationResponse(const std::string& response) noexcept {

        if (response.empty()) {
            return unexpected(ErrBadRequest().WithDetails("No response given"));
        }

        try {

            auto credentialCreationResponse = json(response).get<CredentialCreationResponseType>();
            return ParsedCredentialCreationDataType::Parse(credentialCreationResponse);
        } catch(const std::exception& e) {
            return unexpected(ErrBadRequest().WithDetails("Parse error for Registration").WithInfo(e.what()));
        }
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CREDENTIAL_IPP */
