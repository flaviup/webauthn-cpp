//
//  Metadata.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_METADATA_IPP
#define WEBAUTHN_METADATA_IPP

#define JSON_DISABLE_ENUM_SERIALIZATION 1

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <nlohmann/json.hpp>
#include "../Protocol/Core.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Metadata {

    using json = nlohmann::json;

    struct PublicKeyCredentialParametersType {

        PublicKeyCredentialParametersType() noexcept = default;
        PublicKeyCredentialParametersType(const json& j) :
            Type(j["type"].get<std::string>()),
            Alg(j["alg"].get<WebAuthN::Protocol::WebAuthNCOSE::COSEAlgorithmIdentifierType>()) {
        }

	    std::string Type;
	    WebAuthN::Protocol::WebAuthNCOSE::COSEAlgorithmIdentifierType Alg;
    };

    inline void to_json(json& j, const PublicKeyCredentialParametersType& publicKeyCredentialParameters) {

        j = json{
            {"type", publicKeyCredentialParameters.Type},
            {"alg", publicKeyCredentialParameters.Alg}
        };
    }

    inline void from_json(const json& j, PublicKeyCredentialParametersType& publicKeyCredentialParameters) {

        j.at("type").get_to(publicKeyCredentialParameters.Type);
        j.at("alg").get_to(publicKeyCredentialParameters.Alg);
    }

	// https://secure.globalsign.com/cacert/root-r3.crt
	inline const std::string PRODUCTION_MDS_ROOT = "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpHWD9f";
	// https://mds3.fido.tools/pki/MDS3ROOT.crt
	inline const std::string CONFORMANCE_MDS_ROOT = "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtFIE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBGQUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSLTKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8TEirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAWgBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMygX2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=";
	// Example from https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
	inline const std::string EXAMPLE_MDS_ROOT = "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";

    enum class PublicKeyAlgAndEncodingType {

        // Raw ANSI X9.62 formatted Elliptic Curve public key.
        ALG_KEY_ECC_X962_RAW,
        // DER ITU-X690-2008 encoded ANSI X.9.62 formatted SubjectPublicKeyInfo RFC5480 specifying an elliptic curve public key.
        ALG_KEY_ECC_X962_DER,
        // Raw encoded 2048-bit RSA public key RFC3447.
        ALG_KEY_RSA_2048_RAW,
        // ASN.1 DER [ITU-X690-2008] encoded 2048-bit RSA RFC3447 public key RFC4055.
        ALG_KEY_RSA_2048_DER,
        // COSE_Key format, as defined in Section 7 of RFC8152. This encoding includes its own field for indicating the public key algorithm.
        ALG_KEY_COSE,
        INVALID
    };

    // map PublicKeyAlgAndEncodingType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(PublicKeyAlgAndEncodingType, {
        {PublicKeyAlgAndEncodingType::INVALID, nullptr},
        {PublicKeyAlgAndEncodingType::INVALID, ""},
        {PublicKeyAlgAndEncodingType::ALG_KEY_ECC_X962_RAW, "ecc_x962_raw"},
        {PublicKeyAlgAndEncodingType::ALG_KEY_ECC_X962_DER, "ecc_x962_der"},
        {PublicKeyAlgAndEncodingType::ALG_KEY_RSA_2048_RAW, "rsa_2048_raw"},
        {PublicKeyAlgAndEncodingType::ALG_KEY_RSA_2048_DER, "rsa_2048_der"},
        {PublicKeyAlgAndEncodingType::ALG_KEY_COSE, "cose"}
    })

    enum class AuthenticationAlgorithmType {

        // An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW,
        // DER ITU-X690-2008 encoded ECDSA signature RFC5480 on the NIST secp256r1 curve.
        ALG_SIGN_SECP256R1_ECDSA_SHA256_DER,
        // RSASSA-PSS RFC3447 signature must have raw S buffers, encoded in big-endian order RFC4055 RFC4056.
        ALG_SIGN_RSASSA_PSS_SHA256_RAW,
        // DER ITU-X690-2008 encoded OCTET STRING (not BIT STRING!) containing the RSASSA-PSS RFC3447 signature RFC4055 RFC4056.
        ALG_SIGN_RSASSA_PSS_SHA256_DER,
        // An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW,
        // DER ITU-X690-2008 encoded ECDSA signature RFC5480 on the secp256k1 curve.
        ALG_SIGN_SECP256K1_ECDSA_SHA256_DER,
        // Chinese SM2 elliptic curve based signature algorithm combined with SM3 hash algorithm OSCCA-SM2 OSCCA-SM3.
        ALG_SIGN_SM2_SM3_RAW,
        // This is the EMSA-PKCS1-v1_5 signature as defined in RFC3447.
        ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW,
        // DER ITU-X690-2008 encoded OCTET STRING (not BIT STRING!) containing the EMSA-PKCS1-v1_5 signature as defined in RFC3447.
        ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER,
        // RSASSA-PSS RFC3447 signature must have raw S buffers, encoded in big-endian order RFC4055 RFC4056.
        ALG_SIGN_RSASSA_PSS_SHA384_RAW,
        // RSASSA-PSS RFC3447 signature must have raw S buffers, encoded in big-endian order RFC4055 RFC4056.
        ALG_SIGN_RSASSA_PSS_SHA512_RAW,
        // RSASSA-PKCS1-v1_5 RFC3447 with SHA256(aka RS256) signature must have raw S buffers, encoded in big-endian order RFC8017 RFC4056
        ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW,
        // RSASSA-PKCS1-v1_5 RFC3447 with SHA384(aka RS384) signature must have raw S buffers, encoded in big-endian order RFC8017 RFC4056
        ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW,
        // RSASSA-PKCS1-v1_5 RFC3447 with SHA512(aka RS512) signature must have raw S buffers, encoded in big-endian order RFC8017 RFC4056
        ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW,
        // RSASSA-PKCS1-v1_5 RFC3447 with SHA1(aka RS1) signature must have raw S buffers, encoded in big-endian order RFC8017 RFC4056
        ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW,
        // An ECDSA signature on the NIST secp384r1 curve with SHA384(aka: ES384) which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW,
        // An ECDSA signature on the NIST secp512r1 curve with SHA512(aka: ES512) which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW,
        // An EdDSA signature on the curve 25519, which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_ED25519_EDDSA_SHA512_RAW,
        // An EdDSA signature on the curve Ed448, which must have raw R and S buffers, encoded in big-endian order.
        ALG_SIGN_ED448_EDDSA_SHA512_RAW,
        INVALID
    };

    // map AuthenticationAlgorithmType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticationAlgorithmType, {
        {AuthenticationAlgorithmType::INVALID, nullptr},
        {AuthenticationAlgorithmType::INVALID, ""},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, "secp256r1_ecdsa_sha256_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, "secp256r1_ecdsa_sha256_der"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_RAW, "rsassa_pss_sha256_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_DER, "rsassa_pss_sha256_der"},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW, "secp256k1_ecdsa_sha256_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_DER, "secp256k1_ecdsa_sha256_der"},
        {AuthenticationAlgorithmType::ALG_SIGN_SM2_SM3_RAW, "sm2_sm3_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW, "rsa_emsa_pkcs1_sha256_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER, "rsa_emsa_pkcs1_sha256_der"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA384_RAW, "rsassa_pss_sha384_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA512_RAW, "rsassa_pss_sha512_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW, "rsassa_pkcsv15_sha256_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW, "rsassa_pkcsv15_sha384_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW, "rsassa_pkcsv15_sha512_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW, "rsassa_pkcsv15_sha1_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW, "secp384r1_ecdsa_sha384_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW, "secp521r1_ecdsa_sha512_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_ED25519_EDDSA_SHA512_RAW, "ed25519_eddsa_sha512_raw"},
        {AuthenticationAlgorithmType::ALG_SIGN_ED448_EDDSA_SHA512_RAW, "ed448_eddsa_sha512_raw"}
    })


    // VersionType - Represents a generic version with major and minor fields.
    struct VersionType {

        VersionType() noexcept = default;

        // Major version.
        uint16_t Major; //`json:"major"`
        // Minor version.
        uint16_t Minor; // `json:"minor"`
    };

    // MetadataStatementType - Authenticator metadata statements are used directly by the FIDO server at a relying party, but the information contained in the authoritative statement is used in several other places.
    struct MetadataStatementType {

        MetadataStatementType() noexcept = default;

        // The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement.
        std::string LegalHeader; // `json:"legalHeader"`
        // The Authenticator Attestation ID.
        std::string Aaid; // `json:"aaid"`
        // The Authenticator Attestation GUID.
        std::string AaGUID;// `json:"aaguid"`
        // A list of the attestation certificate public key identifiers encoded as hex string.
        std::vector<std::string> AttestationCertificateKeyIdentifiers; // `json:"attestationCertificateKeyIdentifiers"`
        // A human-readable, short description of the authenticator, in English.
        std::string Description; // `json:"description"`
        // A list of human-readable short descriptions of the authenticator in different languages.
        std::map<std::string, std::string> AlternativeDescriptions; // `json:"alternativeDescriptions"`
        // Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
        uint32_t AuthenticatorVersion; // `json:"authenticatorVersion"`
        // The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
        std::string ProtocolFamily; // `json:"protocolFamily"`
        // The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
        std::vector<VersionType> Upv; //`json:"upv"`
        // The list of authentication algorithms supported by the authenticator.
        std::vector<AuthenticationAlgorithmType> AuthenticationAlgorithms; // `json:"authenticationAlgorithms"`
        // The list of public key formats supported by the authenticator during registration operations.
        std::vector<PublicKeyAlgAndEncodingType> PublicKeyAlgAndEncodings; //`json:"publicKeyAlgAndEncodings"`
        // The supported attestation type(s).
        std::vector<AuthenticatorAttestationType> AttestationTypes;// `json:"attestationTypes"`
        // A list of alternative VerificationMethodANDCombinations.
        std::vector<std::vector<VerificationMethodDescriptorType>> UserVerificationDetails; // `json:"userVerificationDetails"`
        // A 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values
        std::vector<std::string> KeyProtection;// `json:"keyProtection"`
        // This entry is set to true or it is omitted, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
        // This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions.
        bool IsKeyRestricted; //`json:"isKeyRestricted"`
        // This entry is set to true or it is omitted, if Uauth key usage always requires a fresh user verification
        // This entry is set to false, if the Uauth key can be used without requiring a fresh user verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
        bool IsFreshUserVerificationRequired; // `json:"isFreshUserVerificationRequired"`
        // A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values
        std::vector<std::string> MatcherProtection;// `json:"matcherProtection"`
        // The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
        uint16_t CryptoStrength; // `json:"cryptoStrength"`
        // A 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values
        std::vector<std::string> AttachmentHint; // `json:"attachmentHint"`
        // A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values
        std::vector<std::string> TcDisplay; // `json:"tcDisplay"`
        // Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
        std::string TcDisplayContentType; // `json:"tcDisplayContentType"`
        // A list of alternative DisplayPNGCharacteristicsDescriptor. Each of these entries is one alternative of supported image characteristics for displaying a PNG image.
        std::vector<DisplayPNGCharacteristicsDescriptorType> TcDisplayPNGCharacteristics; // `json:"tcDisplayPNGCharacteristics"`
        // Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
        // Multiple certificates might be used for different batches of the same model.
        // The array does not represent a certificate chain, but only the trust anchor of that chain.
        // A trust anchor can be a root certificate, an intermediate CA certificate or even the attestation certificate itself.
        std::vector<std::string> AttestationRootCertificates;// `json:"attestationRootCertificates"`
        // A list of trust anchors used for ECDAA attestation. This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
        std::vector<EcdaaTrustAnchorType> EcdaaTrustAnchors; //`json:"ecdaaTrustAnchors"`
        // A data: url [RFC2397] encoded PNG [PNG] icon for the Authenticator.
        std::string Icon; // `json:"icon"`
        // List of extensions supported by the authenticator.
        std::vector<ExtensionDescriptorType> SupportedExtensions; // `json:"supportedExtensions"`
        // Describes supported versions, extensions, AAGUID of the device and its capabilities
        AuthenticatorGetInfoType AuthenticatorGetInfo; // `json:"authenticatorGetInfo"`
    };

    // MetadataBLOBPayloadEntryType - Represents the MetadataBLOBPayloadEntryType
    // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
    struct MetadataBLOBPayloadEntryType {

        MetadataBLOBPayloadEntryType() noexcept = default;


        // The Authenticator Attestation ID.
        std::string Aaid; // `json:"aaid"`
        // The Authenticator Attestation GUID.
        std::string AaGUID; // `json:"aaguid"`
        // A list of the attestation certificate public key identifiers encoded as hex string.
        std::vector<std::string> AttestationCertificateKeyIdentifiers; // `json:"attestationCertificateKeyIdentifiers"`
        // The metadataStatement JSON object as defined in FIDOMetadataStatement.
        MetadataStatementType MetadataStatement; // `json:"metadataStatement"`
        // Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator
        std::vector<BiometricStatusReportType> BiometricStatusReports; //`json:"biometricStatusReports"`
        // An array of status reports applicable to this authenticator.
        std::vector<StatusReportType> StatusReports; //`json:"statusReports"`
        // ISO-8601 formatted date since when the status report array was set to the current value.
        std::string TimeOfLastStatusChange; // `json:"timeOfLastStatusChange"`
        // URL of a list of rogue (i.e. untrusted) individual authenticators.
        std::string RogueListURL; //`json:"rogueListURL"`
        // The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]).
        std::string RogueListHash; // `json:"rogueListHash"`
    };

    // Metadata is a map of authenticator AAGUIDs to corresponding metadata statements
    std::map<uuid.UUID, MetadataBLOBPayloadEntryType> Metadata{};

    // Conformance indicates if test metadata is currently being used
    auto Conformance = false;

    auto MDSRoot = PRODUCTION_MDS_ROOT;

} // namespace WebAuthN::Metadata

#pragma GCC visibility pop

#endif /* WEBAUTHN_METADATA_IPP */