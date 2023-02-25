//
//  Options.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_OPTIONS_IPP
#define WEBAUTHN_PROTOCOL_OPTIONS_IPP

#include "Entities.ipp"
#include "Authenticator.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // AuthenticationExtensionsType represents the AuthenticationExtensionsClientInputsType IDL. This member contains additional
    // parameters requesting additional processing by the client and authenticator.
    //
    // Specification: §5.7.1. Authentication Extensions Client Inputs (https://www.w3.org/TR/webauthn/#iface-authentication-extensions-client-inputs)
    using ExtensionsType = std::string;
    using AuthenticationExtensionsType = std::map<std::string, ExtensionsType>;

    // CredentialTypeType represents the PublicKeyCredentialType IDL and is used with the CredentialDescriptorType IDL.
    //
    // This enumeration defines the valid credential types. It is an extension point; values can be added to it in the
    // future, as more credential types are defined. The values of this enumeration are used for versioning the
    // Authentication Assertion and attestation structures according to the type of the authenticator.
    //
    // Currently one credential type is defined, namely "public-key".
    //
    // Specification: §5.8.2. Credential Type Enumeration (https://www.w3.org/TR/webauthn/#enumdef-publickeycredentialtype)
    //
    // Specification: §5.8.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#dictionary-credential-descriptor)
    enum class CredentialTypeType {

        // PublicKey - Currently one credential type is defined, namely "public-key".
        PublicKey,
        Invalid // Invalid value
    };

    // map CredentialTypeType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(CredentialTypeType, {
        { CredentialTypeType::Invalid,        nullptr },
        { CredentialTypeType::Invalid,             "" },
        { CredentialTypeType::PublicKey, "public-key" }
    })

    // CredentialParameterType is the credential type and algorithm
    // that the relying party wants the authenticator to create.
    struct CredentialParameterType {

        CredentialParameterType() noexcept = default;
        CredentialParameterType(const json& j) :
            Type(j["type"].get<CredentialTypeType>()),
            Algorithm(j["alg"].get<WebAuthNCOSE::COSEAlgorithmIdentifierType>()) {
        }
        CredentialParameterType(CredentialTypeType type, WebAuthNCOSE::COSEAlgorithmIdentifierType algorithm) noexcept :
            Type(type),
            Algorithm(algorithm) {
        }
        CredentialParameterType(const CredentialParameterType& credentialParameter) noexcept = default;
        CredentialParameterType(CredentialParameterType&& credentialParameter) noexcept = default;
        ~CredentialParameterType() noexcept = default;

        CredentialParameterType& operator =(const CredentialParameterType& other) noexcept = default;
        CredentialParameterType& operator =(CredentialParameterType&& other) noexcept = default;

        CredentialTypeType Type;
        WebAuthNCOSE::COSEAlgorithmIdentifierType Algorithm;
    };

    inline void to_json(json& j, const CredentialParameterType& credentialParameter) {

        j = json{
            { "type",     credentialParameter.Type },
            { "alg", credentialParameter.Algorithm }
        };
    }

    inline void from_json(const json& j, CredentialParameterType& credentialParameter) {

        j.at("type").get_to(credentialParameter.Type);
        j.at("alg").get_to(credentialParameter.Algorithm);
    }

    // CredentialDescriptorType represents the PublicKeyCredentialDescriptorType IDL.
    //
    // This dictionary contains the attributes that are specified by a caller when referring to a public key credential as
    // an input parameter to the create() or get() methods. It mirrors the fields of the PublicKeyCredentialType object returned
    // by the latter methods.
    //
    // Specification: §5.10.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#credential-dictionary)
    struct CredentialDescriptorType {

        CredentialDescriptorType() noexcept = default;
        CredentialDescriptorType(const CredentialType& type,
            const URLEncodedBase64Type& credentialID,
            const std::optional<std::vector<AuthenticatorTransportType>>& transports,
            const std::string& attestationType
            ) noexcept : 
            Type(type), 
            CredentialID(credentialID),
            Transports(transports),
            AttestationType(attestationType) {
        }
        CredentialDescriptorType(const json& j) :
            Type(j["type"].get<CredentialType>()),
            CredentialID(j["id"].get<URLEncodedBase64Type>()) {

            if (j.find("transports") != j.end()) {
                Transports.emplace(j["transports"].get<std::vector<AuthenticatorTransportType>>());
            }
        }
        CredentialDescriptorType(const CredentialDescriptorType& credentialDescriptor) noexcept = default;
        CredentialDescriptorType(CredentialDescriptorType&& credentialDescriptor) noexcept = default;
        ~CredentialDescriptorType() noexcept = default;

        CredentialDescriptorType& operator =(const CredentialDescriptorType& other) noexcept = default;
        CredentialDescriptorType& operator =(CredentialDescriptorType&& other) noexcept = default;
        
        // The valid credential types.
        CredentialType Type;

        // CredentialID The ID of a credential to allow/disallow.
        URLEncodedBase64Type CredentialID;

        // The authenticator transports that can be used.
        std::optional<std::vector<AuthenticatorTransportType>> Transports;

        // The AttestationType from the Credential. Used internally only.
        std::string AttestationType;
    };

    inline void to_json(json& j, const CredentialDescriptorType& credentialDescriptor) {

        j = json{
            { "type",       credentialDescriptor.Type },
            { "id", credentialDescriptor.CredentialID }
        };

        if (credentialDescriptor.Transports) {
            j["transports"] = credentialDescriptor.Transports.value();
        }
    }

    inline void from_json(const json& j, CredentialDescriptorType& credentialDescriptor) {

        j.at("type").get_to(credentialDescriptor.Type);
        j.at("id").get_to(credentialDescriptor.CredentialID);

        if (j.find("transports") != j.end()) {
            credentialDescriptor.Transports.emplace(j["transports"].get<std::vector<AuthenticatorTransportType>>());
        }
    }

    // AuthenticatorSelectionType represents the AuthenticatorSelectionCriteriaType IDL.
    //
    // WebAuthn Relying Parties may use the AuthenticatorSelectionCriteriaType dictionary to specify their requirements
    // regarding authenticator attributes.
    //
    // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dictionary-authenticatorSelection)
    struct AuthenticatorSelectionType {
        
        AuthenticatorSelectionType() noexcept = default;
        AuthenticatorSelectionType(const std::optional<AuthenticatorAttachmentType>& authenticatorAttachment,
            const std::optional<bool>& requireResidentKey,
            const std::optional<ResidentKeyRequirementType>& residentKey,
            const std::optional<UserVerificationRequirementType>& userVerification
            ) noexcept : 
            AuthenticatorAttachment(authenticatorAttachment),
            RequireResidentKey(requireResidentKey),
            ResidentKey(residentKey),
            UserVerification(userVerification) {
        }
        AuthenticatorSelectionType(const json& j) {

            if (j.find("authenticatorAttachment") != j.end()) {
                AuthenticatorAttachment.emplace(j["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
            }

            if (j.find("requireResidentKey") != j.end()) {
                RequireResidentKey.emplace(j["requireResidentKey"].get<bool>());
            }

            if (j.find("residentKey") != j.end()) {
                ResidentKey.emplace(j["residentKey"].get<ResidentKeyRequirementType>());
            }

            if (j.find("userVerification") != j.end()) {
                UserVerification.emplace(j["userVerification"].get<UserVerificationRequirementType>());
            }
        }
        AuthenticatorSelectionType(const AuthenticatorSelectionType& authenticatorSelection) noexcept = default;
        AuthenticatorSelectionType(AuthenticatorSelectionType&& authenticatorSelection) noexcept = default;
        ~AuthenticatorSelectionType() noexcept = default;

        AuthenticatorSelectionType& operator =(const AuthenticatorSelectionType& other) noexcept = default;
        AuthenticatorSelectionType& operator =(AuthenticatorSelectionType&& other) noexcept = default;

        // AuthenticatorAttachment If this member is present, eligible authenticators are filtered to only
        // authenticators attached with the specified AuthenticatorAttachmentType enum.
        std::optional<AuthenticatorAttachmentType> AuthenticatorAttachment;

        // RequireResidentKey this member describes the Relying Party's requirements regarding resident
        // credentials. If the parameter is set to true, the authenticator MUST create a client-side-resident
        // public key credential source when creating a public key credential.
        std::optional<bool> RequireResidentKey; // *bool

        // ResidentKey this member describes the Relying Party's requirements regarding resident
        // credentials per Webauthn Level 2.
        std::optional<ResidentKeyRequirementType> ResidentKey;

        // UserVerification This member describes the Relying Party's requirements regarding user verification for
        // the create() operation. Eligible authenticators are filtered to only those capable of satisfying this
        // requirement.
        std::optional<UserVerificationRequirementType> UserVerification;
    };

    inline void to_json(json& j, const AuthenticatorSelectionType& authenticatorSelection) {

        j = json{};

        if (authenticatorSelection.AuthenticatorAttachment) {
            j["authenticatorAttachment"] = authenticatorSelection.AuthenticatorAttachment.value();
        }

        if (authenticatorSelection.RequireResidentKey) {
            j["requireResidentKey"] = authenticatorSelection.RequireResidentKey.value();
        }

        if (authenticatorSelection.ResidentKey) {
            j["residentKey"] = authenticatorSelection.ResidentKey.value();
        }

        if (authenticatorSelection.UserVerification) {
            j["userVerification"] = authenticatorSelection.UserVerification.value();
        }
    }

    inline void from_json(const json& j, AuthenticatorSelectionType& authenticatorSelection) {

        if (j.find("authenticatorAttachment") != j.end()) {
            authenticatorSelection.AuthenticatorAttachment.emplace(j["authenticatorAttachment"].get<AuthenticatorAttachmentType>());
        }

        if (j.find("requireResidentKey") != j.end()) {
            authenticatorSelection.RequireResidentKey.emplace(j["requireResidentKey"].get<bool>());
        }

        if (j.find("residentKey") != j.end()) {
            authenticatorSelection.ResidentKey.emplace(j["residentKey"].get<ResidentKeyRequirementType>());
        }

        if (j.find("userVerification") != j.end()) {
            authenticatorSelection.UserVerification.emplace(j["userVerification"].get<UserVerificationRequirementType>());
        }
    }

    // ConveyancePreferenceType is the type representing the AttestationConveyancePreferenceType IDL.
    //
    // WebAuthn Relying Parties may use AttestationConveyancePreference to specify their preference regarding attestation
    // conveyance during credential generation.
    //
    // Specification: §5.4.7. Attestation Conveyance Preference Enumeration (https://www.w3.org/TR/webauthn/#enum-attestation-convey)
    enum class ConveyancePreferenceType {

        // NoAttestation is a ConveyancePreferenceType value.
        //
        // This value indicates that the Relying Party is not interested in authenticator attestation. For example, in order
        // to potentially avoid having to obtain user consent to relay identifying information to the Relying Party, or to
        // save a round trip to an Attestation CA or Anonymization CA.
        //
        // This is the default value.
        //
        // Specification: §5.4.7. Attestation Conveyance Preference Enumeration (https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none)
        NoAttestation,

        // IndirectAttestation is a ConveyancePreferenceType value.
        //
        // This value indicates that the Relying Party prefers an attestation conveyance yielding verifiable attestation
        // statements, but allows the client to decide how to obtain such attestation statements. The client MAY replace the
        // authenticator-generated attestation statements with attestation statements generated by an Anonymization CA, in
        // order to protect the user’s privacy, or to assist Relying Parties with attestation verification in a
        // heterogeneous ecosystem.
        //
        // Note: There is no guarantee that the Relying Party will obtain a verifiable attestation statement in this case.
        // For example, in the case that the authenticator employs self attestation.
        //
        // Specification: §5.4.7. Attestation Conveyance Preference Enumeration (https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect)
        IndirectAttestation,

        // DirectAttestation is a ConveyancePreferenceType value.
        //
        // This value indicates that the Relying Party wants to receive the attestation statement as generated by the
        // authenticator.
        //
        // Specification: §5.4.7. Attestation Conveyance Preference Enumeration (https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct)
        DirectAttestation,

        // EnterpriseAttestation is a ConveyancePreferenceType value.
        //
        // This value indicates that the Relying Party wants to receive an attestation statement that may include uniquely
        // identifying information. This is intended for controlled deployments within an enterprise where the organization
        // wishes to tie registrations to specific authenticators. User agents MUST NOT provide such an attestation unless
        // the user agent or authenticator configuration permits it for the requested RP ID.
        //
        // If permitted, the user agent SHOULD signal to the authenticator (at invocation time) that enterprise
        // attestation is requested, and convey the resulting AAGUID and attestation statement, unaltered, to the Relying
        // Party.
        //
        // Specification: §5.4.7. Attestation Conveyance Preference Enumeration (https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-enterprise)
        EnterpriseAttestation,

        // Invalid value
        Invalid
    };

    // map ConveyancePreferenceType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(ConveyancePreferenceType, {
        { ConveyancePreferenceType::Invalid,                    nullptr },
        { ConveyancePreferenceType::Invalid,                         "" },
        { ConveyancePreferenceType::NoAttestation,               "none" },
        { ConveyancePreferenceType::IndirectAttestation,     "indirect" },
        { ConveyancePreferenceType::DirectAttestation,         "direct" },
        { ConveyancePreferenceType::EnterpriseAttestation, "enterprise" }
    })

    // PublicKeyCredentialCreationOptionsType represents the IDL of the same name.
    //
    // In order to create a Credential via create(), the caller specifies a few parameters in a
    // PublicKeyCredentialCreationOptionsType object.
    //
    // TODO: There is one field missing from this for WebAuthn Level 3. A string slice named 'attestationFormats'.
    //
    // Specification: §5.4. Options for Credential Creation (https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions)
    struct PublicKeyCredentialCreationOptionsType {

        PublicKeyCredentialCreationOptionsType() noexcept = default;
        PublicKeyCredentialCreationOptionsType(const RelyingPartyEntityType& relyingParty,
            const UserEntityType& user,
            const URLEncodedBase64Type& challenge,
            const std::optional<std::vector<CredentialParameterType>>& parameters = std::nullopt,
            const std::optional<int64_t>& timeout = std::nullopt,
            const std::optional<std::vector<CredentialDescriptorType>>& credentialExcludeList = std::nullopt,
            const std::optional<AuthenticatorSelectionType>& authenticatorSelection = std::nullopt,
            const std::optional<ConveyancePreferenceType>& attestation = std::nullopt,
            const std::optional<AuthenticationExtensionsType>& extensions = std::nullopt) noexcept :
            RelyingParty(relyingParty),
            User(user),
            Challenge(challenge),
            Parameters(parameters),
            Timeout(timeout),
            CredentialExcludeList(credentialExcludeList),
            AuthenticatorSelection(authenticatorSelection),
            Attestation(attestation),
            Extensions(extensions) {
        };
        PublicKeyCredentialCreationOptionsType(const json& j) :
            RelyingParty(j["rp"].get<RelyingPartyEntityType>()),
            User(j["user"].get<UserEntityType>()),
            Challenge(j["challenge"].get<URLEncodedBase64Type>()) {

            if (j.find("pubKeyCredParams") != j.end()) {
                Parameters.emplace(j["pubKeyCredParams"].get<std::vector<CredentialParameterType>>());
            }

            if (j.find("timeout") != j.end()) {
                Timeout.emplace(j["timeout"].get<int64_t>());
            }

            if (j.find("excludeCredentials") != j.end()) {
                CredentialExcludeList.emplace(j["excludeCredentials"].get<std::vector<CredentialDescriptorType>>());
            }

            if (j.find("authenticatorSelection") != j.end()) {
                AuthenticatorSelection.emplace(j["authenticatorSelection"].get<AuthenticatorSelectionType>());
            }

            if (j.find("attestation") != j.end()) {
                Attestation.emplace(j["attestation"].get<ConveyancePreferenceType>());
            }

            if (j.find("extensions") != j.end()) {
                Extensions.emplace(j["extensions"].get<AuthenticationExtensionsType>());
            }
        }
        PublicKeyCredentialCreationOptionsType(const PublicKeyCredentialCreationOptionsType& publicKeyCredentialCreationOptions) noexcept = default;
        PublicKeyCredentialCreationOptionsType(PublicKeyCredentialCreationOptionsType&& publicKeyCredentialCreationOptions) noexcept = default;
        ~PublicKeyCredentialCreationOptionsType() noexcept = default;

        PublicKeyCredentialCreationOptionsType& operator =(const PublicKeyCredentialCreationOptionsType& other) noexcept = default;
        PublicKeyCredentialCreationOptionsType& operator =(PublicKeyCredentialCreationOptionsType&& other) noexcept = default;

        RelyingPartyEntityType RelyingParty;
        UserEntityType User;
        URLEncodedBase64Type Challenge;
        std::optional<std::vector<CredentialParameterType>> Parameters;
        std::optional<int64_t> Timeout;
        std::optional<std::vector<CredentialDescriptorType>> CredentialExcludeList;
        std::optional<AuthenticatorSelectionType> AuthenticatorSelection;
        std::optional<ConveyancePreferenceType> Attestation;
        std::optional<AuthenticationExtensionsType> Extensions;
    };

    inline void to_json(json& j, const PublicKeyCredentialCreationOptionsType& publicKeyCredentialCreationOptions) {

        j = json{
            { "rp",     publicKeyCredentialCreationOptions.RelyingParty },
            { "user",           publicKeyCredentialCreationOptions.User },
            { "challenge", publicKeyCredentialCreationOptions.Challenge }
        };

        if (publicKeyCredentialCreationOptions.Parameters) {
            j["pubKeyCredParams"] = publicKeyCredentialCreationOptions.Parameters.value();
        }

        if (publicKeyCredentialCreationOptions.Timeout) {
            j["timeout"] = publicKeyCredentialCreationOptions.Timeout.value();
        }

        if (publicKeyCredentialCreationOptions.CredentialExcludeList) {
            j["excludeCredentials"] = publicKeyCredentialCreationOptions.CredentialExcludeList.value();
        }

        if (publicKeyCredentialCreationOptions.AuthenticatorSelection) {
            j["authenticatorSelection"] = publicKeyCredentialCreationOptions.AuthenticatorSelection.value();
        }

        if (publicKeyCredentialCreationOptions.Attestation) {
            j["attestation"] = publicKeyCredentialCreationOptions.Attestation.value();
        }

        if (publicKeyCredentialCreationOptions.Extensions) {
            j["extensions"] = publicKeyCredentialCreationOptions.Extensions.value();
        }
    }

    inline void from_json(const json& j, PublicKeyCredentialCreationOptionsType& publicKeyCredentialCreationOptions) {

        j.at("rp").get_to(publicKeyCredentialCreationOptions.RelyingParty);
        j.at("user").get_to(publicKeyCredentialCreationOptions.User);
        j.at("challenge").get_to(publicKeyCredentialCreationOptions.Challenge);

        if (j.find("pubKeyCredParams") != j.end()) {
            publicKeyCredentialCreationOptions.Parameters.emplace(j["pubKeyCredParams"].get<std::vector<CredentialParameterType>>());
        }

        if (j.find("timeout") != j.end()) {
            publicKeyCredentialCreationOptions.Timeout.emplace(j["timeout"].get<int64_t>());
        }

        if (j.find("excludeCredentials") != j.end()) {
            publicKeyCredentialCreationOptions.CredentialExcludeList.emplace(j["excludeCredentials"].get<std::vector<CredentialDescriptorType>>());
        }

        if (j.find("authenticatorSelection") != j.end()) {
            publicKeyCredentialCreationOptions.AuthenticatorSelection.emplace(j["authenticatorSelection"].get<AuthenticatorSelectionType>());
        }

        if (j.find("attestation") != j.end()) {
            publicKeyCredentialCreationOptions.Attestation.emplace(j["attestation"].get<ConveyancePreferenceType>());
        }

        if (j.find("extensions") != j.end()) {
            publicKeyCredentialCreationOptions.Extensions.emplace(j["extensions"].get<AuthenticationExtensionsType>());
        }
    }

    // The PublicKeyCredentialRequestOptionsType dictionary supplies get() with the data it needs to generate an assertion.
    // Its challenge member MUST be present, while its other members are OPTIONAL.
    //
    // TODO: There are two fields missing from this for WebAuthn Level 3. A string type named 'attestation', and a string
    // slice named 'attestationFormats'.
    //
    // Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)
    struct PublicKeyCredentialRequestOptionsType {

        PublicKeyCredentialRequestOptionsType() noexcept = default;
        PublicKeyCredentialRequestOptionsType(const json& j) :
            Challenge(j["challenge"].get<URLEncodedBase64Type>()) {

            if (j.find("timeout") != j.end()) {
                Timeout.emplace(j["timeout"].get<int>());
            }

            if (j.find("rpId") != j.end()) {
                RelyingPartyID.emplace(j["rpId"].get<std::string>());
            }

            if (j.find("allowCredentials") != j.end()) {
                AllowedCredentials.emplace(j["allowCredentials"].get<std::vector<CredentialDescriptorType>>());
            }

            if (j.find("userVerification") != j.end()) {
                UserVerification.emplace(j["userVerification"].get<UserVerificationRequirementType>());
            }

            if (j.find("extensions") != j.end()) {
                Extensions.emplace(j["extensions"].get<AuthenticationExtensionsType>());
            }
        }
        PublicKeyCredentialRequestOptionsType(const PublicKeyCredentialRequestOptionsType& publicKeyCredentialRequestOptions) noexcept = default;
        PublicKeyCredentialRequestOptionsType(PublicKeyCredentialRequestOptionsType&& publicKeyCredentialRequestOptions) noexcept = default;
        ~PublicKeyCredentialRequestOptionsType() noexcept = default;

        PublicKeyCredentialRequestOptionsType& operator =(const PublicKeyCredentialRequestOptionsType& other) noexcept = default;
        PublicKeyCredentialRequestOptionsType& operator =(PublicKeyCredentialRequestOptionsType&& other) noexcept = default;

        std::vector<URLEncodedBase64Type> GetAllowedCredentialIDs() const noexcept {

            if (AllowedCredentials) {
                std::vector<URLEncodedBase64Type> allowedCredentialIDs(AllowedCredentials.value().size());

                for (const auto& credential : AllowedCredentials.value()) {
                    allowedCredentialIDs.push_back(credential.CredentialID);
                }

                return allowedCredentialIDs;
            }

            return std::vector<URLEncodedBase64Type>(0);
        }

        URLEncodedBase64Type Challenge;
        std::optional<int> Timeout;
        std::optional<std::string> RelyingPartyID;
        std::optional<std::vector<CredentialDescriptorType>> AllowedCredentials;
        std::optional<UserVerificationRequirementType> UserVerification;
        std::optional<AuthenticationExtensionsType> Extensions;
    };

    inline void to_json(json& j, const PublicKeyCredentialRequestOptionsType& publicKeyCredentialRequestOptions) {

        j = json{
            { "challenge", publicKeyCredentialRequestOptions.Challenge }
        };

        if (publicKeyCredentialRequestOptions.Timeout) {
            j["timeout"] = publicKeyCredentialRequestOptions.Timeout.value();
        }

        if (publicKeyCredentialRequestOptions.RelyingPartyID) {
            j["rpId"] = publicKeyCredentialRequestOptions.RelyingPartyID.value();
        }

        if (publicKeyCredentialRequestOptions.AllowedCredentials) {
            j["allowCredentials"] = publicKeyCredentialRequestOptions.AllowedCredentials.value();
        }

        if (publicKeyCredentialRequestOptions.UserVerification) {
            j["userVerification"] = publicKeyCredentialRequestOptions.UserVerification.value();
        }

        if (publicKeyCredentialRequestOptions.Extensions) {
            j["extensions"] = publicKeyCredentialRequestOptions.Extensions.value();
        }
    }

    inline void from_json(const json& j, PublicKeyCredentialRequestOptionsType& publicKeyCredentialRequestOptions) {

        j.at("challenge").get_to(publicKeyCredentialRequestOptions.Challenge);


        if (j.find("timeout") != j.end()) {
            publicKeyCredentialRequestOptions.Timeout.emplace(j["timeout"].get<int>());
        }

        if (j.find("rpId") != j.end()) {
            publicKeyCredentialRequestOptions.RelyingPartyID.emplace(j["rpId"].get<std::string>());
        }

        if (j.find("allowCredentials") != j.end()) {
            publicKeyCredentialRequestOptions.AllowedCredentials.emplace(j["allowCredentials"].get<std::vector<CredentialDescriptorType>>());
        }

        if (j.find("userVerification") != j.end()) {
            publicKeyCredentialRequestOptions.UserVerification.emplace(j["userVerification"].get<UserVerificationRequirementType>());
        }

        if (j.find("extensions") != j.end()) {
            publicKeyCredentialRequestOptions.Extensions.emplace(j["extensions"].get<AuthenticationExtensionsType>());
        }
    }

    struct CredentialCreationType {

        CredentialCreationType() noexcept = default;
        CredentialCreationType(const PublicKeyCredentialCreationOptionsType& response) noexcept :
            Response(response) {
        };
        CredentialCreationType(const json& j) :
            Response(j["publicKey"].get<PublicKeyCredentialCreationOptionsType>()) {
        }
        CredentialCreationType(const CredentialCreationType& credentialCreation) noexcept = default;
        CredentialCreationType(CredentialCreationType&& credentialCreation) noexcept = default;
        ~CredentialCreationType() noexcept = default;

        CredentialCreationType& operator =(const CredentialCreationType& other) noexcept = default;
        CredentialCreationType& operator =(CredentialCreationType&& other) noexcept = default;
        
        PublicKeyCredentialCreationOptionsType Response;
    };

    inline void to_json(json& j, const CredentialCreationType& credentialCreation) {

        j = json{
            { "publicKey", credentialCreation.Response }
        };
    }

    inline void from_json(const json& j, CredentialCreationType& credentialCreation) {

        j.at("publicKey").get_to(credentialCreation.Response);
    }

    struct CredentialAssertionType {

        CredentialAssertionType() noexcept = default;
        CredentialAssertionType(const json& j) :
            Response(j["publicKey"].get<PublicKeyCredentialRequestOptionsType>()) {
        }
        CredentialAssertionType(const CredentialAssertionType& credentialAssertion) noexcept = default;
        CredentialAssertionType(CredentialAssertionType&& credentialAssertion) noexcept = default;
        ~CredentialAssertionType() noexcept = default;

        CredentialAssertionType& operator =(const CredentialAssertionType& other) noexcept = default;
        CredentialAssertionType& operator =(CredentialAssertionType&& other) noexcept = default;
        
        PublicKeyCredentialRequestOptionsType Response;
    };

    inline void to_json(json& j, const CredentialAssertionType& credentialAssertion) {

        j = json{
            { "publicKey", credentialAssertion.Response }
        };
    }

    inline void from_json(const json& j, CredentialAssertionType& credentialAssertion) {

        j.at("publicKey").get_to(credentialAssertion.Response);
    }

    enum class ServerResponseStatusType {

        Ok,
        Failed,
        Invalid  // Invalid value
    };

    // map ServerResponseStatusType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(ServerResponseStatusType, {
        { ServerResponseStatusType::Invalid, nullptr },
        { ServerResponseStatusType::Invalid,      "" },
        { ServerResponseStatusType::Ok,         "ok" },
        { ServerResponseStatusType::Failed, "failed" }
    })

    struct ServerResponseType {

        ServerResponseType() noexcept = default;
        ServerResponseType(const json& j) :
            Status(j["status"].get<ServerResponseStatusType>()),
            Message(j["errorMessage"].get<std::string>()) {
        }
        ServerResponseType(const ServerResponseType& serverResponse) noexcept = default;
        ServerResponseType(ServerResponseType&& serverResponse) noexcept = default;
        ~ServerResponseType() noexcept = default;

        ServerResponseType& operator =(const ServerResponseType& other) noexcept = default;
        ServerResponseType& operator =(ServerResponseType&& other) noexcept = default;

	    ServerResponseStatusType Status;
	    std::string Message;
    };

    inline void to_json(json& j, const ServerResponseType& serverResponse) {

        j = json{
            { "status",        serverResponse.Status },
            { "errorMessage", serverResponse.Message }
        };
    }

    inline void from_json(const json& j, ServerResponseType& serverResponse) {

        j.at("status").get_to(serverResponse.Status);
        j.at("errorMessage").get_to(serverResponse.Message);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_OPTIONS_IPP */
