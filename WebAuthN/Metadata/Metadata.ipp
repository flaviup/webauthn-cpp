//
//  Metadata.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_METADATA_IPP
#define WEBAUTHN_METADATA_IPP

#include <algorithm>
#include <compare>
#include <string>
#include <vector>
#include <map>
#include <iterator>
#include <optional>
#include <nlohmann/json.hpp>
#include <uuid/uuid.h>
#include "../Core.ipp"
#include "../Protocol/WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Metadata {

    using json = nlohmann::json;

    // Consts and variables

    // https://secure.globalsign.com/cacert/root-r3.crt
    inline const std::string PRODUCTION_MDS_ROOT = "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpHWD9f";
    // https://mds3.fido.tools/pki/MDS3ROOT.crt
    inline const std::string CONFORMANCE_MDS_ROOT = "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtFIE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBGQUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSLTKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8TEirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAWgBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMygX2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=";
    // Example from https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
    inline const std::string EXAMPLE_MDS_ROOT = "MIIGGTCCBAGgAwIBAgIUdT9qLX0sVMRe8l0sLmHd3mZovQ0wDQYJKoZIhvcNAQELBQAwgZsxHzAdBgNVBAMMFkVYQU1QTEUgTURTMyBURVNUIFJPT1QxIjAgBgkqhkiG9w0BCQEWE2V4YW1wbGVAZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT1JHMRAwDgYDVQQLDAdFeGFtcGxlMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0yMTA0MTkxMTM1MDdaFw00ODA5MDQxMTM1MDdaMIGbMR8wHQYDVQQDDBZFWEFNUExFIE1EUzMgVEVTVCBST09UMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlQGV4YW1wbGUuY29tMRQwEgYDVQQKDAtFeGFtcGxlIE9SRzEQMA4GA1UECwwHRXhhbXBsZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDjF5wyEWuhwDHsZosGdGFTCcI677rW881vV+UfW38J+K2ioFFNeGVsxbcebK6AVOiCDPFj0974IpeD9SFOhwAHoDu/LCfXdQWp8ZgQ91ULYWoW8o7NNSp01nbN9zmaO6/xKNCa0bzjmXoGqglqnP1AtRcWYvXOSKZy1rcPeDv4Dhcpdp6W72fBw0eWIqOhsrItuY2/N8ItBPiG03EX72nACq4nZJ/nAIcUbER8STSFPPzvE97TvShsi1FD8aO6l1WkR/QkreAGjMI++GbB2Qc1nN9Y/VEDbMDhQtxXQRdpFwubTjejkN9hKOtF3B71YrwIrng3V9RoPMFdapWMzSlI+WWHog0oTj1PqwJDDg7+z1I6vSDeVWAMKr9mq1w1OGNzgBopIjd9lRWkRtt2kQSPX9XxqS4E1gDDr8MKbpM3JuubQtNCg9D7Ljvbz6vwvUrbPHH+oREvucsp0PZ5PpizloepGIcLFxDQqCulGY2n7Ahl0JOFXJqOFCaK3TWHwBvZsaY5DgBuUvdUrwtgZNg2eg2omWXEepiVFQn3Fvj43Wh2npPMgIe5P0rwncXvROxaczd4rtajKS1ucoB9b9iKqM2+M1y/FDIgVf1fWEHwK7YdzxMlgOeLdeV/kqRU5PEUlLU9a2EwdOErrPbPKZmIfbs/L4B3k4zejMDH3Y+ZwIDAQABo1MwUTAdBgNVHQ4EFgQU8sWwq1TrurK7xMTwO1dKfeJBbCMwHwYDVR0jBBgwFoAU8sWwq1TrurK7xMTwO1dKfeJBbCMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAFw6M1PiIfCPIBQ5EBUPNmRvRFuDpolOmDofnf/+mv63LqwQZAdo/W8tzZ9kOFhq24SiLw0H7fsdG/jeREXiIZMNoW/rA6Uac8sU+FYF7Q+qp6CQLlSQbDcpVMifTQjcBk2xh+aLK9SrrXBqnTAhwS+offGtAW8DpoLuH4tAcQmIjlgMlN65jnELCuqNR/wpA+zch8LZW8saQ2cwRCwdr8mAzZoLbsDSVCHxQF3/kQjPT7Nao1q2iWcY3OYcRmKrieHDP67yeLUbVmetfZis2d6ZlkqHLB4ZW1xX4otsEFkuTJA3HWDRsNyhTwx1YoCLsYut5Zp0myqPNBq28w6qGMyyoJN0Z4RzMEO3R6i/MQNfhK55/8O2HciM6xb5t/aBSuHPKlBDrFWhpRnKYkaNtlUo35qV5IbKGKau3SdZdSRciaXUd/p81YmoF01UlhhMz/Rqr1k2gyA0a9tF8+awCeanYt5izl8YO0FlrOU1SQ5UQw4szqqZqbrf4e8fRuU2TXNx4zk+ImE7WRB44f6mSD746ZCBRogZ/SA5jUBu+OPe4/sEtERWRcQD+fXgce9ZEN0+peyJIKAsl5Rm2Bmgyg5IoyWwSG5W+WekGyEokpslou2Yc6EjUj5ndZWz5EiHAiQ74hNfDoCZIxVVLU3Qbp8a0S1bmsoT2JOsspIbtZUg=";
    
    inline auto MDSRoot = PRODUCTION_MDS_ROOT;

    // Conformance indicates if test metadata is currently being used
    inline auto Conformance = false;

    // Enums

    // AuthenticatorAttestationType - The ATTESTATION constants are 16 bit long integers indicating the specific attestation that authenticator supports.
    // Each constant has a case-sensitive string representation (in quotes), which is used in the authoritative metadata for FIDO authenticators.
    enum class AuthenticatorAttestationType {
        // BasicFull - Indicates full basic attestation, based on an attestation private key shared among a class of authenticators (e.g. same model). Authenticators must provide its attestation signature during the registration process for the same reason. The attestation trust anchor is shared with FIDO Servers out of band (as part of the Metadata). This sharing process should be done according to [UAFMetadataService].
        BasicFull,
        // BasicSurrogate - Just syntactically a Basic Attestation. The attestation object self-signed, i.e. it is signed using the UAuth.priv key, i.e. the key corresponding to the UAuth.pub key included in the attestation object. As a consequence it does not provide a cryptographic proof of the security characteristics. But it is the best thing we can do if the authenticator is not able to have an attestation private key.
        BasicSurrogate,
        // Ecdaa - Indicates use of elliptic curve based direct anonymous attestation as defined in [FIDOEcdaaAlgorithm]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
        Ecdaa,
        // AttCA - Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
        AttCA,
        // AnonCA In this case, the authenticator uses an Anonymization CA which dynamically generates per-credential attestation certificates such that the attestation statements presented to Relying Parties do not provide uniquely identifiable information, e.g., that might be used for tracking purposes. The applicable [WebAuthn] attestation formats "fmt" are Google SafetyNet Attestation "android-safetynet", Android Keystore Attestation "android-key", Apple Anonymous Attestation "apple", and Apple Application Attestation "apple-appattest".
        AnonCA,
        // None - Indicates absence of attestation
        None,
        // Invalid value
        Invalid = -1
    };

    // map AuthenticatorAttestationType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticatorAttestationType, {
        { AuthenticatorAttestationType::Invalid,                  nullptr },
        { AuthenticatorAttestationType::Invalid,                       "" },
        { AuthenticatorAttestationType::BasicFull,           "basic_full" },
        { AuthenticatorAttestationType::BasicSurrogate, "basic_surrogate" },
        { AuthenticatorAttestationType::Ecdaa,                    "ecdaa" },
        { AuthenticatorAttestationType::AttCA,                    "attca" },
        { AuthenticatorAttestationType::AnonCA,                  "anonca" },
        { AuthenticatorAttestationType::None,                      "none" }
    })

    // AuthenticatorStatusType - This enumeration describes the status of an authenticator model as identified by its AAID and potentially some additional information (such as a specific attestation key).
    // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum
    enum class AuthenticatorStatusType {
        // NotFidoCertified - This authenticator is not FIDO certified.
        NotFidoCertified,
        // FidoCertified - This authenticator has passed FIDO functional certification. This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
        FidoCertified,
        // UserVerificationBypass - Indicates that malware is able to bypass the user verification. This means that the authenticator could be used without the user's consent and potentially even without the user's knowledge.
        UserVerificationBypass,
        // AttestationKeyCompromise - Indicates that an attestation key for this authenticator is known to be compromised. Additional data should be supplied, including the key identifier and the date of compromise, if known.
        AttestationKeyCompromise,
        // UserKeyRemoteCompromise - This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted. This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.
        UserKeyRemoteCompromise,
        // UserKeyPhysicalCompromise - This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
        UserKeyPhysicalCompromise,
        // UpdateAvailable - A software or firmware update is available for the device. Additional data should be supplied including a URL where users can obtain an update and the date the update was published.
        UpdateAvailable,
        // Revoked - The FIDO Alliance has determined that this authenticator should not be trusted for any reason, for example if it is known to be a fraudulent product or contain a deliberate backdoor.
        Revoked,
        // SelfAssertionSubmitted - The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance. If this completed checklist is publicly available, the URL will be specified in StatusReport.url.
        SelfAssertionSubmitted,
        // FidoCertifiedL1 - The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.
        FidoCertifiedL1,
        // FidoCertifiedL1plus - The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level 1.
        FidoCertifiedL1plus,
        // FidoCertifiedL2 - The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1+.
        FidoCertifiedL2,
        // FidoCertifiedL2plus - The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level 2.
        FidoCertifiedL2plus,
        // FidoCertifiedL3 - The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2+.
        FidoCertifiedL3,
        // FidoCertifiedL3plus - The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level 3.
        FidoCertifiedL3plus,
        // Invalid value
        Invalid = -1
    };

    // map AuthenticatorStatusType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticatorStatusType, {
        { AuthenticatorStatusType::Invalid,                                          nullptr },
        { AuthenticatorStatusType::Invalid,                                               "" },
        { AuthenticatorStatusType::NotFidoCertified,                    "NOT_FIDO_CERTIFIED" },
        { AuthenticatorStatusType::FidoCertified,                           "FIDO_CERTIFIED" },
        { AuthenticatorStatusType::UserVerificationBypass,        "USER_VERIFICATION_BYPASS" },
        { AuthenticatorStatusType::AttestationKeyCompromise,    "ATTESTATION_KEY_COMPROMISE" },
        { AuthenticatorStatusType::UserKeyRemoteCompromise,     "USER_KEY_REMOTE_COMPROMISE" },
        { AuthenticatorStatusType::UserKeyPhysicalCompromise, "USER_KEY_PHYSICAL_COMPROMISE" },
        { AuthenticatorStatusType::UpdateAvailable,                       "UPDATE_AVAILABLE" },
        { AuthenticatorStatusType::Revoked,                                        "REVOKED" },
        { AuthenticatorStatusType::SelfAssertionSubmitted,        "SELF_ASSERTION_SUBMITTED" },
        { AuthenticatorStatusType::FidoCertifiedL1,                      "FIDO_CERTIFIED_L1" },
        { AuthenticatorStatusType::FidoCertifiedL1plus,              "FIDO_CERTIFIED_L1plus" },
        { AuthenticatorStatusType::FidoCertifiedL2,                      "FIDO_CERTIFIED_L2" },
        { AuthenticatorStatusType::FidoCertifiedL2plus,              "FIDO_CERTIFIED_L2plus" },
        { AuthenticatorStatusType::FidoCertifiedL3,                      "FIDO_CERTIFIED_L3" },
        { AuthenticatorStatusType::FidoCertifiedL3plus,              "FIDO_CERTIFIED_L3plus" }
    })

    // UNDESIRED_AUTHENTICATOR_STATUS is an array of undesirable authenticator statuses
    inline constexpr const AuthenticatorStatusType UNDESIRED_AUTHENTICATOR_STATUS[] = {
        AuthenticatorStatusType::Invalid,
        AuthenticatorStatusType::UserVerificationBypass,
        AuthenticatorStatusType::AttestationKeyCompromise,
        AuthenticatorStatusType::UserKeyRemoteCompromise,
        AuthenticatorStatusType::UserKeyPhysicalCompromise,
        AuthenticatorStatusType::Revoked
    };

    // IsUndesiredAuthenticatorStatus returns whether the supplied authenticator status is desirable or not
    inline bool IsUndesiredAuthenticatorStatus(AuthenticatorStatusType status) noexcept {

        return std::find(std::cbegin(UNDESIRED_AUTHENTICATOR_STATUS), std::cend(UNDESIRED_AUTHENTICATOR_STATUS), status) != std::cend(UNDESIRED_AUTHENTICATOR_STATUS);
    }

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
        // Invalid value
        ALG_KEY_INVALID = -1
    };

    // map PublicKeyAlgAndEncodingType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(PublicKeyAlgAndEncodingType, {
        { PublicKeyAlgAndEncodingType::ALG_KEY_INVALID,             nullptr },
        { PublicKeyAlgAndEncodingType::ALG_KEY_INVALID,                  "" },
        { PublicKeyAlgAndEncodingType::ALG_KEY_ECC_X962_RAW, "ecc_x962_raw" },
        { PublicKeyAlgAndEncodingType::ALG_KEY_ECC_X962_DER, "ecc_x962_der" },
        { PublicKeyAlgAndEncodingType::ALG_KEY_RSA_2048_RAW, "rsa_2048_raw" },
        { PublicKeyAlgAndEncodingType::ALG_KEY_RSA_2048_DER, "rsa_2048_der" },
        { PublicKeyAlgAndEncodingType::ALG_KEY_COSE,                 "cose" }
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
        // Invalid value
        ALG_INVALID = -1
    };

    // map AuthenticationAlgorithmType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticationAlgorithmType, {
        { AuthenticationAlgorithmType::ALG_INVALID,                                              nullptr },
        { AuthenticationAlgorithmType::ALG_INVALID,                                                   "" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, "secp256r1_ecdsa_sha256_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, "secp256r1_ecdsa_sha256_der" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_RAW,           "rsassa_pss_sha256_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_DER,           "rsassa_pss_sha256_der" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW, "secp256k1_ecdsa_sha256_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_DER, "secp256k1_ecdsa_sha256_der" },
        { AuthenticationAlgorithmType::ALG_SIGN_SM2_SM3_RAW,                               "sm2_sm3_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW,   "rsa_emsa_pkcs1_sha256_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER,   "rsa_emsa_pkcs1_sha256_der" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA384_RAW,           "rsassa_pss_sha384_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA512_RAW,           "rsassa_pss_sha512_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW,   "rsassa_pkcsv15_sha256_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW,   "rsassa_pkcsv15_sha384_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW,   "rsassa_pkcsv15_sha512_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW,       "rsassa_pkcsv15_sha1_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW, "secp384r1_ecdsa_sha384_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW, "secp521r1_ecdsa_sha512_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_ED25519_EDDSA_SHA512_RAW,     "ed25519_eddsa_sha512_raw" },
        { AuthenticationAlgorithmType::ALG_SIGN_ED448_EDDSA_SHA512_RAW,         "ed448_eddsa_sha512_raw" }
    })

    // Structs

    namespace WebAuthNCOSE = ::WebAuthN::Protocol::WebAuthNCOSE;

    // TODO: this goes away after WebAuthNCOSE::CredentialPublicKey gets implemented
/*    struct AlgKeyCose {
        
        WebAuthNCOSE::COSEKeyType KeyType;
        WebAuthNCOSE::COSEAlgorithmIdentifierType Algorithm;
        WebAuthNCOSE::COSEEllipticCurveType Curve;

        constexpr auto operator <=>(const AlgKeyCose&) const noexcept = default;
    };

#pragma GCC visibility push(hidden)

    namespace {

        static inline const auto _MAPPING = std::map<AuthenticationAlgorithmType, AlgKeyCose>{
            { AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::P256 } },
            { AuthenticationAlgorithmType::ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::P256 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_RAW,      { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS256 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA256_DER,      { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS256 } },
            { AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256K, .Curve = WebAuthNCOSE::COSEEllipticCurveType::Secp256k1 } },
            { AuthenticationAlgorithmType::ALG_SIGN_SECP256K1_ECDSA_SHA256_DER, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256K, .Curve = WebAuthNCOSE::COSEEllipticCurveType::Secp256k1 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA384_RAW,      { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS384 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PSS_SHA512_RAW,      { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgPS512 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW,  { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS256 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW,  { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS384 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW,  { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS512 } },
            { AuthenticationAlgorithmType::ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW,    { .KeyType = WebAuthNCOSE::COSEKeyType::RSAKey,      .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgRS1 } },
            { AuthenticationAlgorithmType::ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES384,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::P384 } },
            { AuthenticationAlgorithmType::ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW, { .KeyType = WebAuthNCOSE::COSEKeyType::EllipticKey, .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES512,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::P521 } },
            { AuthenticationAlgorithmType::ALG_SIGN_ED25519_EDDSA_SHA512_RAW,   { .KeyType = WebAuthNCOSE::COSEKeyType::OctetKey,    .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgEdDSA,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::Ed25519 } },
            { AuthenticationAlgorithmType::ALG_SIGN_ED448_EDDSA_SHA512_RAW,     { .KeyType = WebAuthNCOSE::COSEKeyType::OctetKey,    .Algorithm = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgEdDSA,  .Curve = WebAuthNCOSE::COSEEllipticCurveType::Ed448 } }
        };

        static inline const AlgKeyCose& _AlgKeyCoseMappingFunction(AuthenticationAlgorithmType authAlgorithm) noexcept {

            return _MAPPING.find(authAlgorithm)->second;
        }
    } // namespace

#pragma GCC visibility pop*/

    // usage:
    // algKeyCose key = ...;
    // AuthenticationAlgorithmType a[] = {
    //     AuthenticationAlgorithmType::ALG_SIGN_ED25519_EDDSA_SHA512_RAW,
    //     AuthenticationAlgorithmType::ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER,
    //     ........
    // };
    // AlgKeyMatch(key, a);
    /*template<size_t N>
    inline bool AlgKeyMatch(const AlgKeyCose& key, AuthenticationAlgorithmType (&algs)[N]) noexcept {

        for (auto it = std::cbegin(algs); it != std::cend(algs); ++it) {

            if (_AlgKeyCoseMappingFunction(*it) == key) {

                return true;
            }
        }

        return false;
    }*/

    struct PublicKeyCredentialParametersType {

        PublicKeyCredentialParametersType() noexcept = default;

        PublicKeyCredentialParametersType(const json& j) :
            Type(j["type"].get<std::string>()),
            Alg(j["alg"].get<WebAuthNCOSE::COSEAlgorithmIdentifierType>()) {
        }

        PublicKeyCredentialParametersType(const PublicKeyCredentialParametersType& publicKeyCredentialParameters) noexcept = default;
        PublicKeyCredentialParametersType(PublicKeyCredentialParametersType&& publicKeyCredentialParameters) noexcept = default;
        ~PublicKeyCredentialParametersType() noexcept = default;

        PublicKeyCredentialParametersType& operator =(const PublicKeyCredentialParametersType& other) noexcept = default;
        PublicKeyCredentialParametersType& operator =(PublicKeyCredentialParametersType&& other) noexcept = default;

        std::string Type;
        WebAuthNCOSE::COSEAlgorithmIdentifierType Alg;
    };

    inline void to_json(json& j, const PublicKeyCredentialParametersType& publicKeyCredentialParameters) {

        j = json{
            { "type",                   publicKeyCredentialParameters.Type },
            { "alg",   static_cast<int>(publicKeyCredentialParameters.Alg) }
        };
    }

    inline void from_json(const json& j, PublicKeyCredentialParametersType& publicKeyCredentialParameters) {

        j.at("type").get_to(publicKeyCredentialParameters.Type);
        j.at("alg").get_to(publicKeyCredentialParameters.Alg);
    }

    struct AuthenticatorGetInfoType {

        AuthenticatorGetInfoType() noexcept = default;

        AuthenticatorGetInfoType(const json& j) :
            Versions(j["versions"].get<std::vector<std::string>>()),
            AaGUID(j["aaguid"].get<std::string>()) {

            if (j.find("extensions") != j.end()) {
                Extensions.emplace(j["extensions"].get<std::vector<std::string>>());
            }

            if (j.find("options") != j.end()) {
                Options.emplace(j["options"].get<std::map<std::string, bool>>());
            }

            if (j.find("maxMsgSize") != j.end()) {
                MaxMsgSize.emplace(j["maxMsgSize"].get<uint32_t>());
            }

            if (j.find("pinUvAuthProtocols") != j.end()) {
                PinUvAuthProtocols.emplace(j["pinUvAuthProtocols"].get<std::vector<uint32_t>>());
            }

            if (j.find("maxCredentialCountInList") != j.end()) {
                MaxCredentialCountInList.emplace(j["maxCredentialCountInList"].get<uint32_t>());
            }

            if (j.find("maxCredentialIdLength") != j.end()) {
                MaxCredentialIdLength.emplace(j["maxCredentialIdLength"].get<uint32_t>());
            }

            if (j.find("transports") != j.end()) {
                Transports.emplace(j["transports"].get<std::vector<std::string>>());
            }

            if (j.find("algorithms") != j.end()) {
                Algorithms.emplace(j["algorithms"].get<std::vector<PublicKeyCredentialParametersType>>());
            }

            if (j.find("maxSerializedLargeBlobArray") != j.end()) {
                MaxSerializedLargeBlobArray.emplace(j["maxSerializedLargeBlobArray"].get<uint32_t>());
            }

            if (j.find("forcePINChange") != j.end()) {
                ForcePINChange.emplace(j["forcePINChange"].get<bool>());
            }

            if (j.find("minPINLength") != j.end()) {
                MinPINLength.emplace(j["minPINLength"].get<uint32_t>());
            }

            if (j.find("firmwareVersion") != j.end()) {
                FirmwareVersion.emplace(j["firmwareVersion"].get<uint32_t>());
            }

            if (j.find("maxCredBlobLength") != j.end()) {
                MaxCredBlobLength.emplace(j["maxCredBlobLength"].get<uint32_t>());
            }

            if (j.find("maxRPIDsForSetMinPINLength") != j.end()) {
                MaxRPIDsForSetMinPINLength.emplace(j["maxRPIDsForSetMinPINLength"].get<uint32_t>());
            }

            if (j.find("preferredPlatformUvAttempts") != j.end()) {
                PreferredPlatformUvAttempts.emplace(j["preferredPlatformUvAttempts"].get<uint32_t>());
            }

            if (j.find("uvModality") != j.end()) {
                UvModality.emplace(j["uvModality"].get<uint32_t>());
            }

            if (j.find("certifications") != j.end()) {
                Certifications.emplace(j["certifications"].get<std::map<std::string, double>>());
            }

            if (j.find("remainingDiscoverableCredentials") != j.end()) {
                RemainingDiscoverableCredentials.emplace(j["remainingDiscoverableCredentials"].get<uint32_t>());
            }

            if (j.find("vendorPrototypeConfigCommands") != j.end()) {
                VendorPrototypeConfigCommands.emplace(j["vendorPrototypeConfigCommands"].get<std::vector<uint32_t>>());
            }
        }

        AuthenticatorGetInfoType(const AuthenticatorGetInfoType& authenticatorGetInfo) noexcept = default;
        AuthenticatorGetInfoType(AuthenticatorGetInfoType&& authenticatorGetInfo) noexcept = default;
        ~AuthenticatorGetInfoType() noexcept = default;

        AuthenticatorGetInfoType& operator =(const AuthenticatorGetInfoType& other) noexcept = default;
        AuthenticatorGetInfoType& operator =(AuthenticatorGetInfoType&& other) noexcept = default;

        // List of supported versions.
        std::vector<std::string> Versions;
        // List of supported extensions.
        std::optional<std::vector<std::string>> Extensions;
        // The claimed AAGUID.
        std::string AaGUID;
        // List of supported options.
        std::optional<std::map<std::string, bool>> Options;
        // Maximum message size supported by the authenticator.
        std::optional<uint32_t> MaxMsgSize;
        // List of supported PIN/UV auth protocols in order of decreasing authenticator preference.
        std::optional<std::vector<uint32_t>> PinUvAuthProtocols;
        // Maximum number of credentials supported in credentialID list at a time by the authenticator.
        std::optional<uint32_t> MaxCredentialCountInList;
        // Maximum Credential ID Length supported by the authenticator.
        std::optional<uint32_t> MaxCredentialIdLength;
        // List of supported transports.
        std::optional<std::vector<std::string>> Transports;
        // List of supported algorithms for credential generation, as specified in WebAuthn.
        std::optional<std::vector<PublicKeyCredentialParametersType>> Algorithms;
        // The maximum size, in bytes, of the serialized large-blob array that this authenticator can store.
        std::optional<uint32_t> MaxSerializedLargeBlobArray;
        // If this member is present and set to true, the PIN must be changed.
        std::optional<bool> ForcePINChange;
        // This specifies the current minimum PIN length, in Unicode code points, the authenticator enforces for ClientPIN.
        std::optional<uint32_t> MinPINLength;
        // Indicates the firmware version of the authenticator model identified by AAGUID.
        std::optional<uint32_t> FirmwareVersion;
        // Maximum credBlob length in bytes supported by the authenticator.
        std::optional<uint32_t> MaxCredBlobLength;
        // This specifies the max number of RP IDs that authenticator can set via setMinPINLength subcommand.
        std::optional<uint32_t> MaxRPIDsForSetMinPINLength;
        // This specifies the preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions subCommand the platform may attempt before falling back to the getPinUvAuthTokenUsingPinWithPermissions subCommand or displaying an error.
        std::optional<uint32_t> PreferredPlatformUvAttempts;
        // This specifies the user verification modality supported by the authenticator via authenticatorClientPIN's getPinUvAuthTokenUsingUvWithPermissions subcommand.
        std::optional<uint32_t> UvModality;
        // This specifies a list of authenticator certifications.
        std::optional<std::map<std::string, double>> Certifications;
        // If this member is present it indicates the estimated number of additional discoverable credentials that can be stored.
        std::optional<uint32_t> RemainingDiscoverableCredentials;
        // If present the authenticator supports the authenticatorConfig vendorPrototype subcommand, and its value is a list of authenticatorConfig vendorCommandId values supported, which MAY be empty.
        std::optional<std::vector<uint32_t>> VendorPrototypeConfigCommands;
    };

    inline void to_json(json& j, const AuthenticatorGetInfoType& authenticatorGetInfo) {

        j = json{
            { "versions", authenticatorGetInfo.Versions }
        };

        if (authenticatorGetInfo.Extensions) {
            j["extensions"] = authenticatorGetInfo.Extensions.value();
        }

        j["aaguid"] = authenticatorGetInfo.AaGUID;

        if (authenticatorGetInfo.Options) {
            j["options"] = authenticatorGetInfo.Options.value();
        }

        if (authenticatorGetInfo.MaxMsgSize) {
            j["maxMsgSize"] = authenticatorGetInfo.MaxMsgSize.value();
        }

        if (authenticatorGetInfo.PinUvAuthProtocols) {
            j["pinUvAuthProtocols"] = authenticatorGetInfo.PinUvAuthProtocols.value();
        }

        if (authenticatorGetInfo.MaxCredentialCountInList) {
            j["maxCredentialCountInList"] = authenticatorGetInfo.MaxCredentialCountInList.value();
        }

        if (authenticatorGetInfo.MaxCredentialIdLength) {
            j["maxCredentialIdLength"] = authenticatorGetInfo.MaxCredentialIdLength.value();
        }

        if (authenticatorGetInfo.Transports) {
            j["transports"] = authenticatorGetInfo.Transports.value();
        }

        if (authenticatorGetInfo.Algorithms) {
            j["algorithms"] = authenticatorGetInfo.Algorithms.value();
        }

        if (authenticatorGetInfo.MaxSerializedLargeBlobArray) {
            j["maxSerializedLargeBlobArray"] = authenticatorGetInfo.MaxSerializedLargeBlobArray.value();
        }

        if (authenticatorGetInfo.ForcePINChange) {
            j["forcePINChange"] = authenticatorGetInfo.ForcePINChange.value();
        }

        if (authenticatorGetInfo.MinPINLength) {
            j["minPINLength"] = authenticatorGetInfo.MinPINLength.value();
        }

        if (authenticatorGetInfo.FirmwareVersion) {
            j["firmwareVersion"] = authenticatorGetInfo.FirmwareVersion.value();
        }

        if (authenticatorGetInfo.MaxCredBlobLength) {
            j["maxCredBlobLength"] = authenticatorGetInfo.MaxCredBlobLength.value();
        }

        if (authenticatorGetInfo.MaxRPIDsForSetMinPINLength) {
            j["maxRPIDsForSetMinPINLength"] = authenticatorGetInfo.MaxRPIDsForSetMinPINLength.value();
        }

        if (authenticatorGetInfo.PreferredPlatformUvAttempts) {
            j["preferredPlatformUvAttempts"] = authenticatorGetInfo.PreferredPlatformUvAttempts.value();
        }

        if (authenticatorGetInfo.UvModality) {
            j["uvModality"] = authenticatorGetInfo.UvModality.value();
        }

        if (authenticatorGetInfo.Certifications) {
            j["certifications"] = authenticatorGetInfo.Certifications.value();
        }

        if (authenticatorGetInfo.RemainingDiscoverableCredentials) {
            j["remainingDiscoverableCredentials"] = authenticatorGetInfo.RemainingDiscoverableCredentials.value();
        }

        if (authenticatorGetInfo.VendorPrototypeConfigCommands) {
            j["vendorPrototypeConfigCommands"] = authenticatorGetInfo.VendorPrototypeConfigCommands.value();
        }
    }

    inline void from_json(const json& j, AuthenticatorGetInfoType& authenticatorGetInfo) {

        j.at("versions").get_to(authenticatorGetInfo.Versions);
        j.at("aaguid").get_to(authenticatorGetInfo.AaGUID);

        if (j.find("extensions") != j.end()) {
            authenticatorGetInfo.Extensions.emplace(j["extensions"].get<std::vector<std::string>>());
        }

        if (j.find("options") != j.end()) {
            authenticatorGetInfo.Options.emplace(j["options"].get<std::map<std::string, bool>>());
        }

        if (j.find("maxMsgSize") != j.end()) {
            authenticatorGetInfo.MaxMsgSize.emplace(j["maxMsgSize"].get<uint32_t>());
        }

        if (j.find("pinUvAuthProtocols") != j.end()) {
            authenticatorGetInfo.PinUvAuthProtocols.emplace(j["pinUvAuthProtocols"].get<std::vector<uint32_t>>());
        }

        if (j.find("maxCredentialCountInList") != j.end()) {
            authenticatorGetInfo.MaxCredentialCountInList.emplace(j["maxCredentialCountInList"].get<uint32_t>());
        }

        if (j.find("maxCredentialIdLength") != j.end()) {
            authenticatorGetInfo.MaxCredentialIdLength.emplace(j["maxCredentialIdLength"].get<uint32_t>());
        }

        if (j.find("transports") != j.end()) {
            authenticatorGetInfo.Transports.emplace(j["transports"].get<std::vector<std::string>>());
        }

        if (j.find("algorithms") != j.end()) {
            authenticatorGetInfo.Algorithms.emplace(j["algorithms"].get<std::vector<PublicKeyCredentialParametersType>>());
        }

        if (j.find("maxSerializedLargeBlobArray") != j.end()) {
            authenticatorGetInfo.MaxSerializedLargeBlobArray.emplace(j["maxSerializedLargeBlobArray"].get<uint32_t>());
        }

        if (j.find("forcePINChange") != j.end()) {
            authenticatorGetInfo.ForcePINChange.emplace(j["forcePINChange"].get<bool>());
        }

        if (j.find("minPINLength") != j.end()) {
            authenticatorGetInfo.MinPINLength.emplace(j["minPINLength"].get<uint32_t>());
        }

        if (j.find("firmwareVersion") != j.end()) {
            authenticatorGetInfo.FirmwareVersion.emplace(j["firmwareVersion"].get<uint32_t>());
        }

        if (j.find("maxCredBlobLength") != j.end()) {
            authenticatorGetInfo.MaxCredBlobLength.emplace(j["maxCredBlobLength"].get<uint32_t>());
        }

        if (j.find("maxRPIDsForSetMinPINLength") != j.end()) {
            authenticatorGetInfo.MaxRPIDsForSetMinPINLength.emplace(j["maxRPIDsForSetMinPINLength"].get<uint32_t>());
        }

        if (j.find("preferredPlatformUvAttempts") != j.end()) {
            authenticatorGetInfo.PreferredPlatformUvAttempts.emplace(j["preferredPlatformUvAttempts"].get<uint32_t>());
        }

        if (j.find("uvModality") != j.end()) {
            authenticatorGetInfo.UvModality.emplace(j["uvModality"].get<uint32_t>());
        }

        if (j.find("certifications") != j.end()) {
            authenticatorGetInfo.Certifications.emplace(j["certifications"].get<std::map<std::string, double>>());
        }

        if (j.find("remainingDiscoverableCredentials") != j.end()) {
            authenticatorGetInfo.RemainingDiscoverableCredentials.emplace(j["remainingDiscoverableCredentials"].get<uint32_t>());
        }

        if (j.find("vendorPrototypeConfigCommands") != j.end()) {
            authenticatorGetInfo.VendorPrototypeConfigCommands.emplace(j["vendorPrototypeConfigCommands"].get<std::vector<uint32_t>>());
        }
    }

    // RogueListEntryType - Contains a list of individual authenticators known to be rogue
    struct RogueListEntryType {

        RogueListEntryType() noexcept = default;

        RogueListEntryType(const json& j) :
            Sk(j["sk"].get<std::string>()),
            Date(j["date"].get<std::string>()) {
        }

        RogueListEntryType(const RogueListEntryType& rogueListEntry) noexcept = default;
        RogueListEntryType(RogueListEntryType&& rogueListEntry) noexcept = default;
        ~RogueListEntryType() noexcept = default;

        RogueListEntryType& operator =(const RogueListEntryType& other) noexcept = default;
        RogueListEntryType& operator =(RogueListEntryType&& other) noexcept = default;

        // Base64url encoding of the rogue authenticator's secret key
        std::string Sk;
        // ISO-8601 formatted date since when this entry is effective.
        std::string Date;
    };

    inline void to_json(json& j, const RogueListEntryType& rogueListEntry) {

        j = json{
            { "sk",     rogueListEntry.Sk },
            { "date", rogueListEntry.Date }
        };
    }

    inline void from_json(const json& j, RogueListEntryType& rogueListEntry) {

        j.at("sk").get_to(rogueListEntry.Sk);
        j.at("date").get_to(rogueListEntry.Date);
    }

    // CodeAccuracyDescriptorType describes the relevant accuracy/complexity aspects of passcode user verification methods.
    struct CodeAccuracyDescriptorType {

        CodeAccuracyDescriptorType() noexcept = default;

        CodeAccuracyDescriptorType(const json& j) :
            Base(j["base"].get<uint16_t>()),
            MinLength(j["minLength"].get<uint16_t>()) {

            if (j.find("maxRetries") != j.end()) {
                MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
            }

            if (j.find("blockSlowdown") != j.end()) {
                BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
            }
        }

        CodeAccuracyDescriptorType(const CodeAccuracyDescriptorType& codeAccuracyDescriptor) noexcept = default;
        CodeAccuracyDescriptorType(CodeAccuracyDescriptorType&& codeAccuracyDescriptor) noexcept = default;
        ~CodeAccuracyDescriptorType() noexcept = default;

        CodeAccuracyDescriptorType& operator =(const CodeAccuracyDescriptorType& other) noexcept = default;
        CodeAccuracyDescriptorType& operator =(CodeAccuracyDescriptorType&& other) noexcept = default;

        // The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.
        uint16_t Base;
        // The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
        uint16_t MinLength;
        // Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
        std::optional<uint16_t> MaxRetries;
        // Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
        // 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.
        // All alternative user verification methods MUST be specified appropriately in the Metadata in userVerificationDetails.
        std::optional<uint16_t> BlockSlowdown;
    };

    inline void to_json(json& j, const CodeAccuracyDescriptorType& codeAccuracyDescriptor) {

        j = json{
            { "base",           codeAccuracyDescriptor.Base },
            { "minLength", codeAccuracyDescriptor.MinLength }
        };

        if (codeAccuracyDescriptor.MaxRetries) {
            j["maxRetries"] = codeAccuracyDescriptor.MaxRetries.value();
        }

        if (codeAccuracyDescriptor.BlockSlowdown) {
            j["blockSlowdown"] = codeAccuracyDescriptor.BlockSlowdown.value();
        }
    }

    inline void from_json(const json& j, CodeAccuracyDescriptorType& codeAccuracyDescriptor) {

        j.at("base").get_to(codeAccuracyDescriptor.Base);
        j.at("minLength").get_to(codeAccuracyDescriptor.MinLength);

        if (j.find("maxRetries") != j.end()) {
            codeAccuracyDescriptor.MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
        }

        if (j.find("blockSlowdown") != j.end()) {
            codeAccuracyDescriptor.BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
        }
    }

    // The BiometricAccuracyDescriptorType describes relevant accuracy/complexity aspects in the case of a biometric user verification method.
    struct BiometricAccuracyDescriptorType {

        BiometricAccuracyDescriptorType() noexcept = default;

        BiometricAccuracyDescriptorType(const json& j) {

            if (j.find("selfAttestedFRR") != j.end()) {
                SelfAttestedFRR.emplace(j["selfAttestedFRR"].get<double>());
            }

            if (j.find("selfAttestedFAR") != j.end()) {
                SelfAttestedFAR.emplace(j["selfAttestedFAR"].get<double>());
            }

            if (j.find("maxTemplates") != j.end()) {
                MaxTemplates.emplace(j["maxTemplates"].get<uint16_t>());
            }

            if (j.find("maxRetries") != j.end()) {
                MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
            }

            if (j.find("blockSlowdown") != j.end()) {
                BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
            }
        }

        BiometricAccuracyDescriptorType(const BiometricAccuracyDescriptorType& biometricAccuracyDescriptor) noexcept = default;
        BiometricAccuracyDescriptorType(BiometricAccuracyDescriptorType&& biometricAccuracyDescriptor) noexcept = default;
        ~BiometricAccuracyDescriptorType() noexcept = default;

        BiometricAccuracyDescriptorType& operator =(const BiometricAccuracyDescriptorType& other) noexcept = default;
        BiometricAccuracyDescriptorType& operator =(BiometricAccuracyDescriptorType&& other) noexcept = default;

        // The false rejection rate [ISO19795-1] for a single template, i.e. the percentage of verification transactions with truthful claims of identity that are incorrectly denied.
        std::optional<double> SelfAttestedFRR;
        // The false acceptance rate [ISO19795-1] for a single template, i.e. the percentage of verification transactions with wrongful claims of identity that are incorrectly confirmed.
        std::optional<double> SelfAttestedFAR;
        // Maximum number of alternative templates from different fingers allowed.
        std::optional<uint16_t> MaxTemplates;
        // Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
        std::optional<uint16_t> MaxRetries;
        // Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
        // 0 means that this user verification method will be blocked either permanently or until an alternative user verification method succeeded.
        // All alternative user verification methods MUST be specified appropriately in the metadata in userVerificationDetails.
        std::optional<uint16_t> BlockSlowdown;
    };

    inline void to_json(json& j, const BiometricAccuracyDescriptorType& biometricAccuracyDescriptor) {

        j = json{};

        if (biometricAccuracyDescriptor.SelfAttestedFRR) {
            j["selfAttestedFRR"] = biometricAccuracyDescriptor.SelfAttestedFRR.value();
        }

        if (biometricAccuracyDescriptor.SelfAttestedFAR) {
            j["selfAttestedFAR"] = biometricAccuracyDescriptor.SelfAttestedFAR.value();
        }

        if (biometricAccuracyDescriptor.MaxTemplates) {
            j["maxTemplates"] = biometricAccuracyDescriptor.MaxTemplates.value();
        }
        
        if (biometricAccuracyDescriptor.MaxRetries) {
            j["maxRetries"] = biometricAccuracyDescriptor.MaxRetries.value();
        }

        if (biometricAccuracyDescriptor.BlockSlowdown) {
            j["blockSlowdown"] = biometricAccuracyDescriptor.BlockSlowdown.value();
        }
    }

    inline void from_json(const json& j, BiometricAccuracyDescriptorType& biometricAccuracyDescriptor) {

        if (j.find("selfAttestedFRR") != j.end()) {
            biometricAccuracyDescriptor.SelfAttestedFRR.emplace(j["selfAttestedFRR"].get<double>());
        }

        if (j.find("selfAttestedFAR") != j.end()) {
            biometricAccuracyDescriptor.SelfAttestedFAR.emplace(j["selfAttestedFAR"].get<double>());
        }

        if (j.find("maxTemplates") != j.end()) {
            biometricAccuracyDescriptor.MaxTemplates.emplace(j["maxTemplates"].get<uint16_t>());
        }

        if (j.find("maxRetries") != j.end()) {
            biometricAccuracyDescriptor.MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
        }

        if (j.find("blockSlowdown") != j.end()) {
            biometricAccuracyDescriptor.BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
        }
    }

    // The PatternAccuracyDescriptorType describes relevant accuracy/complexity aspects in the case that a pattern is used as the user verification method.
    struct PatternAccuracyDescriptorType {

        PatternAccuracyDescriptorType() noexcept = default;

        PatternAccuracyDescriptorType(const json& j) :
            MinComplexity(j["minComplexity"].get<uint32_t>()) {

            if (j.find("maxRetries") != j.end()) {
                MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
            }

            if (j.find("blockSlowdown") != j.end()) {
                BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
            }
        }

        PatternAccuracyDescriptorType(const PatternAccuracyDescriptorType& patternAccuracyDescriptor) noexcept = default;
        PatternAccuracyDescriptorType(PatternAccuracyDescriptorType&& patternAccuracyDescriptor) noexcept = default;
        ~PatternAccuracyDescriptorType() noexcept = default;

        PatternAccuracyDescriptorType& operator =(const PatternAccuracyDescriptorType& other) noexcept = default;
        PatternAccuracyDescriptorType& operator =(PatternAccuracyDescriptorType&& other) noexcept = default;

        // Number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.
        uint32_t MinComplexity;
        // Maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.
        std::optional<uint16_t> MaxRetries;
        // Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism).
        // 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.
        // All alternative user verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
        std::optional<uint16_t> BlockSlowdown;
    };

    inline void to_json(json& j, const PatternAccuracyDescriptorType& patternAccuracyDescriptor) {

        j = json{
            { "minComplexity", patternAccuracyDescriptor.MinComplexity }
        };

        if (patternAccuracyDescriptor.MaxRetries) {
            j["maxRetries"] = patternAccuracyDescriptor.MaxRetries.value();
        }

        if (patternAccuracyDescriptor.BlockSlowdown) {
            j["blockSlowdown"] = patternAccuracyDescriptor.BlockSlowdown.value();
        }
    }

    inline void from_json(const json& j, PatternAccuracyDescriptorType& patternAccuracyDescriptor) {

        j.at("minComplexity").get_to(patternAccuracyDescriptor.MinComplexity);

        if (j.find("maxRetries") != j.end()) {
            patternAccuracyDescriptor.MaxRetries.emplace(j["maxRetries"].get<uint16_t>());
        }

        if (j.find("blockSlowdown") != j.end()) {
            patternAccuracyDescriptor.BlockSlowdown.emplace(j["blockSlowdown"].get<uint16_t>());
        }
    }

    // VerificationMethodDescriptorType - A descriptor for a specific base user verification method as implemented by the authenticator.
    struct VerificationMethodDescriptorType {

        VerificationMethodDescriptorType() noexcept = default;

        VerificationMethodDescriptorType(const json& j) {

            if (j.find("userVerificationMethod") != j.end()) {
                UserVerificationMethod.emplace(j["userVerificationMethod"].get<std::string>());
            }

            if (j.find("caDesc") != j.end()) {
                CaDesc.emplace(j["caDesc"].get<CodeAccuracyDescriptorType>());
            }

            if (j.find("baDesc") != j.end()) {
                BaDesc.emplace(j["baDesc"].get<BiometricAccuracyDescriptorType>());
            }

            if (j.find("paDesc") != j.end()) {
                PaDesc.emplace(j["paDesc"].get<PatternAccuracyDescriptorType>());
            }
        }

        VerificationMethodDescriptorType(const VerificationMethodDescriptorType& verificationMethodDescriptor) noexcept = default;
        VerificationMethodDescriptorType(VerificationMethodDescriptorType&& verificationMethodDescriptor) noexcept = default;
        ~VerificationMethodDescriptorType() noexcept = default;

        VerificationMethodDescriptorType& operator =(const VerificationMethodDescriptorType& other) noexcept = default;
        VerificationMethodDescriptorType& operator =(VerificationMethodDescriptorType&& other) noexcept = default;

        // a single USER_VERIFY constant (see [FIDORegistry]), not a bit flag combination. This value MUST be non-zero.
        std::optional<std::string> UserVerificationMethod;
        // May optionally be used in the case of method USER_VERIFY_PASSCODE.
        std::optional<CodeAccuracyDescriptorType> CaDesc;
        // May optionally be used in the case of method USER_VERIFY_FINGERPRINT, USER_VERIFY_VOICEPRINT, USER_VERIFY_FACEPRINT, USER_VERIFY_EYEPRINT, or USER_VERIFY_HANDPRINT.
        std::optional<BiometricAccuracyDescriptorType> BaDesc;
        // May optionally be used in case of method USER_VERIFY_PATTERN.
        std::optional<PatternAccuracyDescriptorType> PaDesc;
    };

    inline void to_json(json& j, const VerificationMethodDescriptorType& verificationMethodDescriptor) {

        j = json{};

        if (verificationMethodDescriptor.UserVerificationMethod) {
            j["userVerificationMethod"] = verificationMethodDescriptor.UserVerificationMethod.value();
        }

        if (verificationMethodDescriptor.CaDesc) {
            j["caDesc"] = verificationMethodDescriptor.CaDesc.value();
        }

        if (verificationMethodDescriptor.BaDesc) {
            j["baDesc"] = verificationMethodDescriptor.BaDesc.value();
        }

        if (verificationMethodDescriptor.PaDesc) {
            j["paDesc"] = verificationMethodDescriptor.PaDesc.value();
        }
    }

    inline void from_json(const json& j, VerificationMethodDescriptorType& verificationMethodDescriptor) {

        if (j.find("userVerificationMethod") != j.end()) {
            verificationMethodDescriptor.UserVerificationMethod.emplace(j["userVerificationMethod"].get<std::string>());
        }

        if (j.find("caDesc") != j.end()) {
            verificationMethodDescriptor.CaDesc.emplace(j["caDesc"].get<CodeAccuracyDescriptorType>());
        }

        if (j.find("baDesc") != j.end()) {
            verificationMethodDescriptor.BaDesc.emplace(j["baDesc"].get<BiometricAccuracyDescriptorType>());
        }

        if (j.find("paDesc") != j.end()) {
            verificationMethodDescriptor.PaDesc.emplace(j["paDesc"].get<PatternAccuracyDescriptorType>());
        }
    }

    // The RGBPaletteEntryType is an RGB three-sample tuple palette entry
    struct RGBPaletteEntryType {

        RGBPaletteEntryType() noexcept = default;

        RGBPaletteEntryType(const json& j) :
            R(j["r"].get<uint16_t>()),
            G(j["g"].get<uint16_t>()),
            B(j["b"].get<uint16_t>()) {
        }

        RGBPaletteEntryType(const RGBPaletteEntryType& rgbPaletteEntry) noexcept = default;
        RGBPaletteEntryType(RGBPaletteEntryType&& rgbPaletteEntry) noexcept = default;
        ~RGBPaletteEntryType() noexcept = default;

        RGBPaletteEntryType& operator =(const RGBPaletteEntryType& other) noexcept = default;
        RGBPaletteEntryType& operator =(RGBPaletteEntryType&& other) noexcept = default;

        // Red channel sample value
        uint16_t R;
        // Green channel sample value
        uint16_t G;
        // Blue channel sample value
        uint16_t B;
    };

    inline void to_json(json& j, const RGBPaletteEntryType& rgbPaletteEntry) {

        j = json{
            { "r", rgbPaletteEntry.R },
            { "g", rgbPaletteEntry.G },
            { "b", rgbPaletteEntry.B }
        };
    }

    inline void from_json(const json& j, RGBPaletteEntryType& rgbPaletteEntry) {

        j.at("r").get_to(rgbPaletteEntry.R);
        j.at("g").get_to(rgbPaletteEntry.G);
        j.at("b").get_to(rgbPaletteEntry.B);
    }

    // The DisplayPNGCharacteristicsDescriptorType describes a PNG image characteristics as defined in the PNG [PNG] spec for IHDR (image header) and PLTE (palette table)
    struct DisplayPNGCharacteristicsDescriptorType {

        DisplayPNGCharacteristicsDescriptorType() noexcept = default;

        DisplayPNGCharacteristicsDescriptorType(const json& j) :
            Width(j["width"].get<uint32_t>()),
            Height(j["height"].get<uint32_t>()),
            BitDepth(j["bitDepth"].get<uint8_t>()),
            ColorType(j["colorType"].get<uint8_t>()),
            Compression(j["compression"].get<uint8_t>()),
            Filter(j["filter"].get<uint8_t>()),
            Interlace(j["interlace"].get<uint8_t>()) {
            
            if (j.find("plte") != j.end()) {
                Plte.emplace(j["plte"].get<std::vector<RGBPaletteEntryType>>());
            }
        }

        DisplayPNGCharacteristicsDescriptorType(const DisplayPNGCharacteristicsDescriptorType& displayPNGCharacteristicsDescriptor) noexcept = default;
        DisplayPNGCharacteristicsDescriptorType(DisplayPNGCharacteristicsDescriptorType&& displayPNGCharacteristicsDescriptor) noexcept = default;
        ~DisplayPNGCharacteristicsDescriptorType() noexcept = default;

        DisplayPNGCharacteristicsDescriptorType& operator =(const DisplayPNGCharacteristicsDescriptorType& other) noexcept = default;
        DisplayPNGCharacteristicsDescriptorType& operator =(DisplayPNGCharacteristicsDescriptorType&& other) noexcept = default;

        // image width
        uint32_t Width;
        // image height
        uint32_t Height;
        // Bit depth - bits per sample or per palette index.
        uint8_t BitDepth;
        // Color type defines the PNG image type.
        uint8_t ColorType;
        // Compression method used to compress the image data.
        uint8_t Compression;
        // Filter method is the preprocessing method applied to the image data before compression.
        uint8_t Filter;
        // Interlace method is the transmission order of the image data.
        uint8_t Interlace;
        // 1 to 256 palette entries
        std::optional<std::vector<RGBPaletteEntryType>> Plte;
    };

    inline void to_json(json& j, const DisplayPNGCharacteristicsDescriptorType& displayPNGCharacteristicsDescriptor) {

        j = json{
            { "width",             displayPNGCharacteristicsDescriptor.Width },
            { "height",           displayPNGCharacteristicsDescriptor.Height },
            { "bitDepth",       displayPNGCharacteristicsDescriptor.BitDepth },
            { "colorType",     displayPNGCharacteristicsDescriptor.ColorType },
            { "compression", displayPNGCharacteristicsDescriptor.Compression },
            { "filter",           displayPNGCharacteristicsDescriptor.Filter },
            { "interlace",     displayPNGCharacteristicsDescriptor.Interlace }
        };

        if (displayPNGCharacteristicsDescriptor.Plte) {
            j["plte"] = displayPNGCharacteristicsDescriptor.Plte.value();
        }
    }

    inline void from_json(const json& j, DisplayPNGCharacteristicsDescriptorType& displayPNGCharacteristicsDescriptor) {

        j.at("width").get_to(displayPNGCharacteristicsDescriptor.Width);
        j.at("height").get_to(displayPNGCharacteristicsDescriptor.Height);
        j.at("bitDepth").get_to(displayPNGCharacteristicsDescriptor.BitDepth);
        j.at("colorType").get_to(displayPNGCharacteristicsDescriptor.ColorType);
        j.at("compression").get_to(displayPNGCharacteristicsDescriptor.Compression);
        j.at("filter").get_to(displayPNGCharacteristicsDescriptor.Filter);
        j.at("interlace").get_to(displayPNGCharacteristicsDescriptor.Interlace);

        if (j.find("plte") != j.end()) {
            displayPNGCharacteristicsDescriptor.Plte.emplace(j["plte"].get<std::vector<RGBPaletteEntryType>>());
        }
    }

    // EcdaaTrustAnchorType - In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor MUST be specified in this field.
    struct EcdaaTrustAnchorType {

        EcdaaTrustAnchorType() noexcept = default;

        EcdaaTrustAnchorType(const json& j) :
            X(j["X"].get<std::string>()),
            Y(j["Y"].get<std::string>()),
            C(j["c"].get<std::string>()),
            SX(j["sx"].get<std::string>()),
            SY(j["sy"].get<std::string>()),
            G1Curve(j["G1Curve"].get<std::string>()) {
        }

        EcdaaTrustAnchorType(const EcdaaTrustAnchorType& ecdaaTrustAnchor) noexcept = default;
        EcdaaTrustAnchorType(EcdaaTrustAnchorType&& ecdaaTrustAnchor) noexcept = default;
        ~EcdaaTrustAnchorType() noexcept = default;

        EcdaaTrustAnchorType& operator =(const EcdaaTrustAnchorType& other) noexcept = default;
        EcdaaTrustAnchorType& operator =(EcdaaTrustAnchorType&& other) noexcept = default;

        // base64url encoding of the result of ECPoint2ToB of the ECPoint2 X
        std::string X;
        // base64url encoding of the result of ECPoint2ToB of the ECPoint2 Y
        std::string Y;
        // base64url encoding of the result of BigNumberToB(c)
        std::string C;
        // base64url encoding of the result of BigNumberToB(sx)
        std::string SX;
        // base64url encoding of the result of BigNumberToB(sy)
        std::string SY;
        // Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.
        std::string G1Curve;
    };

    inline void to_json(json& j, const EcdaaTrustAnchorType& ecdaaTrustAnchor) {

        j = json{
            { "X",             ecdaaTrustAnchor.X },
            { "Y",             ecdaaTrustAnchor.Y },
            { "c",             ecdaaTrustAnchor.C },
            { "sx",           ecdaaTrustAnchor.SX },
            { "sy",           ecdaaTrustAnchor.SY },
            { "G1Curve", ecdaaTrustAnchor.G1Curve }
        };
    }

    inline void from_json(const json& j, EcdaaTrustAnchorType& ecdaaTrustAnchor) {

        j.at("X").get_to(ecdaaTrustAnchor.X);
        j.at("Y").get_to(ecdaaTrustAnchor.Y);
        j.at("c").get_to(ecdaaTrustAnchor.C);
        j.at("sx").get_to(ecdaaTrustAnchor.SX);
        j.at("sy").get_to(ecdaaTrustAnchor.SY);
        j.at("G1Curve").get_to(ecdaaTrustAnchor.G1Curve);
    }

    // ExtensionDescriptorType - This descriptor contains an extension supported by the authenticator.
    struct ExtensionDescriptorType {

        ExtensionDescriptorType() noexcept = default;

        ExtensionDescriptorType(const json& j) :
            ID(j["id"].get<std::string>()),
            FailIfUnknown(j["fail_if_unknown"].get<bool>()) {

            if (j.find("tag") != j.end()) {
                Tag.emplace(j["tag"].get<uint16_t>());
            }

            if (j.find("data") != j.end()) {
                Data.emplace(j["data"].get<std::string>());
            }
        }

        ExtensionDescriptorType(const ExtensionDescriptorType& extensionDescriptor) noexcept = default;
        ExtensionDescriptorType(ExtensionDescriptorType&& extensionDescriptor) noexcept = default;
        ~ExtensionDescriptorType() noexcept = default;

        ExtensionDescriptorType& operator =(const ExtensionDescriptorType& other) noexcept = default;
        ExtensionDescriptorType& operator =(ExtensionDescriptorType&& other) noexcept = default;

        // Identifies the extension.
        std::string ID;
        // The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
        std::optional<uint16_t> Tag;
        // Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.
        std::optional<std::string> Data;
        // Indicates whether unknown extensions must be ignored (false) or must lead to an error (true) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
        bool FailIfUnknown;
    };

    inline void to_json(json& j, const ExtensionDescriptorType& extensionDescriptor) {

        j = json{
            { "id", extensionDescriptor.ID }
        };

        if (extensionDescriptor.Tag) {
            j["tag"] = extensionDescriptor.Tag.value();
        }

        if (extensionDescriptor.Data) {
            j["data"] = extensionDescriptor.Data.value();
        }

        j["fail_if_unknown"] = extensionDescriptor.FailIfUnknown;
    }

    inline void from_json(const json& j, ExtensionDescriptorType& extensionDescriptor) {

        j.at("id").get_to(extensionDescriptor.ID);
        j.at("fail_if_unknown").get_to(extensionDescriptor.FailIfUnknown);

        if (j.find("tag") != j.end()) {
            extensionDescriptor.Tag.emplace(j["tag"].get<uint16_t>());
        }

        if (j.find("data") != j.end()) {
            extensionDescriptor.Data.emplace(j["data"].get<std::string>());
        }
    }

    // VersionType - Represents a generic version with major and minor fields.
    struct VersionType {

        VersionType() noexcept = default;

        VersionType(const json& j) :
            Major(j["major"].get<uint16_t>()),
            Minor(j["minor"].get<uint16_t>()) {
        }

        VersionType(const VersionType& version) noexcept = default;
        VersionType(VersionType&& version) noexcept = default;
        ~VersionType() noexcept = default;

        VersionType& operator =(const VersionType& other) noexcept = default;
        VersionType& operator =(VersionType&& other) noexcept = default;

        // Major version.
        uint16_t Major;
        // Minor version.
        uint16_t Minor;
    };

    inline void to_json(json& j, const VersionType& version) {

        j = json{
            { "major", version.Major },
            { "minor", version.Minor }
        };
    }

    inline void from_json(const json& j, VersionType& version) {

        j.at("major").get_to(version.Major);
        j.at("minor").get_to(version.Minor);
    }

    // MetadataStatementType - Authenticator metadata statements are used directly by the FIDO server at a relying party, but the information contained in the authoritative statement is used in several other places.
    struct MetadataStatementType {

        MetadataStatementType() noexcept = default;

        MetadataStatementType(const json& j) :
            Description(j["description"].get<std::string>()),
            AuthenticatorVersion(j["authenticatorVersion"].get<uint32_t>()),
            ProtocolFamily(j["protocolFamily"].get<std::string>()),
            Schema(j["schema"].get<uint16_t>()),
            Upv(j["upv"].get<std::vector<VersionType>>()),
            AuthenticationAlgorithms(j["authenticationAlgorithms"].get<std::vector<AuthenticationAlgorithmType>>()),
            PublicKeyAlgAndEncodings(j["publicKeyAlgAndEncodings"].get<std::vector<PublicKeyAlgAndEncodingType>>()),
            AttestationTypes(j["attestationTypes"].get<std::vector<AuthenticatorAttestationType>>()),
            UserVerificationDetails(j["userVerificationDetails"].get<std::vector<std::vector<VerificationMethodDescriptorType>>>()),
            KeyProtection(j["keyProtection"].get<std::vector<std::string>>()),
            MatcherProtection(j["matcherProtection"].get<std::vector<std::string>>()),
            TcDisplay(j["tcDisplay"].get<std::vector<std::string>>()),
            AttestationRootCertificates(j["attestationRootCertificates"].get<std::vector<std::string>>()) {

            if (j.find("legalHeader") != j.end()) {
                LegalHeader.emplace(j["legalHeader"].get<std::string>());
            }

            if (j.find("aaid") != j.end()) {
                Aaid.emplace(j["aaid"].get<std::string>());
            }

            if (j.find("aaguid") != j.end()) {
                AaGUID.emplace(j["aaguid"].get<std::string>());
            }

            if (j.find("attestationCertificateKeyIdentifiers") != j.end()) {
                AttestationCertificateKeyIdentifiers.emplace(j["attestationCertificateKeyIdentifiers"].get<std::vector<std::string>>());
            }

            if (j.find("alternativeDescriptions") != j.end()) {
                AlternativeDescriptions.emplace(j["alternativeDescriptions"].get<std::map<std::string, std::string>>());
            }

            if (j.find("isKeyRestricted") != j.end()) {
                IsKeyRestricted.emplace(j["isKeyRestricted"].get<bool>());
            }

            if (j.find("isFreshUserVerificationRequired") != j.end()) {
                IsFreshUserVerificationRequired.emplace(j["isFreshUserVerificationRequired"].get<bool>());
            }

            if (j.find("cryptoStrength") != j.end()) {
                CryptoStrength.emplace(j["cryptoStrength"].get<uint16_t>());
            }

            if (j.find("attachmentHint") != j.end()) {
                AttachmentHint.emplace(j["attachmentHint"].get<std::vector<std::string>>());
            }

            if (j.find("tcDisplayContentType") != j.end()) {
                TcDisplayContentType.emplace(j["tcDisplayContentType"].get<std::string>());
            }

            if (j.find("tcDisplayPNGCharacteristics") != j.end()) {
                TcDisplayPNGCharacteristics.emplace(j["tcDisplayPNGCharacteristics"].get<std::vector<DisplayPNGCharacteristicsDescriptorType>>());
            }

            if (j.find("ecdaaTrustAnchors") != j.end()) {
                EcdaaTrustAnchors.emplace(j["ecdaaTrustAnchors"].get<std::vector<EcdaaTrustAnchorType>>());
            }

            if (j.find("icon") != j.end()) {
                Icon.emplace(j["icon"].get<std::string>());
            }

            if (j.find("supportedExtensions") != j.end()) {
                SupportedExtensions.emplace(j["supportedExtensions"].get<std::vector<ExtensionDescriptorType>>());
            }

            if (j.find("authenticatorGetInfo") != j.end()) {
                AuthenticatorGetInfo.emplace(j["authenticatorGetInfo"].get<AuthenticatorGetInfoType>());
            }
        }

        MetadataStatementType(const MetadataStatementType& metadataStatement) noexcept = default;
        MetadataStatementType(MetadataStatementType&& metadataStatement) noexcept = default;
        ~MetadataStatementType() noexcept = default;

        MetadataStatementType& operator =(const MetadataStatementType& other) noexcept = default;
        MetadataStatementType& operator =(MetadataStatementType&& other) noexcept = default;

        // The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement.
        std::optional<std::string> LegalHeader;
        // The Authenticator Attestation ID.
        std::optional<std::string> Aaid;
        // The Authenticator Attestation GUID.
        std::optional<std::string> AaGUID;
        // A list of the attestation certificate public key identifiers encoded as hex string.
        std::optional<std::vector<std::string>> AttestationCertificateKeyIdentifiers;
        // A human-readable, short description of the authenticator, in English.
        std::string Description;
        // A list of human-readable short descriptions of the authenticator in different languages.
        std::optional<std::map<std::string, std::string>> AlternativeDescriptions;
        // Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
        uint32_t AuthenticatorVersion;
        // The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
        std::string ProtocolFamily;
        // The FIDO Metadata Schema version
        // Metadata schema version defines what schema of the metadata statement is currently present.
        uint16_t Schema;
        // The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
        std::vector<VersionType> Upv;
        // The list of authentication algorithms supported by the authenticator.
        std::vector<AuthenticationAlgorithmType> AuthenticationAlgorithms;
        // The list of public key formats supported by the authenticator during registration operations.
        std::vector<PublicKeyAlgAndEncodingType> PublicKeyAlgAndEncodings;
        // The supported attestation type(s).
        std::vector<AuthenticatorAttestationType> AttestationTypes;
        // A list of alternative VerificationMethodANDCombinations.
        std::vector<std::vector<VerificationMethodDescriptorType>> UserVerificationDetails;
        // A 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values
        std::vector<std::string> KeyProtection;
        // This entry is set to true or it is omitted, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
        // This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions.
        std::optional<bool> IsKeyRestricted;
        // This entry is set to true or it is omitted, if Uauth key usage always requires a fresh user verification
        // This entry is set to false, if the Uauth key can be used without requiring a fresh user verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
        std::optional<bool> IsFreshUserVerificationRequired;
        // A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values
        std::vector<std::string> MatcherProtection;
        // The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
        std::optional<uint16_t> CryptoStrength;
        // A 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values
        std::optional<std::vector<std::string>> AttachmentHint;
        // A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values
        std::vector<std::string> TcDisplay;
        // Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
        std::optional<std::string> TcDisplayContentType;
        // A list of alternative DisplayPNGCharacteristicsDescriptor. Each of these entries is one alternative of supported image characteristics for displaying a PNG image.
        std::optional<std::vector<DisplayPNGCharacteristicsDescriptorType>> TcDisplayPNGCharacteristics;
        // Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
        // Multiple certificates might be used for different batches of the same model.
        // The array does not represent a certificate chain, but only the trust anchor of that chain.
        // A trust anchor can be a root certificate, an intermediate CA certificate or even the attestation certificate itself.
        std::vector<std::string> AttestationRootCertificates;
        // A list of trust anchors used for ECDAA attestation. This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
        std::optional<std::vector<EcdaaTrustAnchorType>> EcdaaTrustAnchors;
        // A data: url [RFC2397] encoded PNG [PNG] icon for the Authenticator.
        std::optional<std::string> Icon;
        // List of extensions supported by the authenticator.
        std::optional<std::vector<ExtensionDescriptorType>> SupportedExtensions;
        // Describes supported versions, extensions, AAGUID of the device and its capabilities
        std::optional<AuthenticatorGetInfoType> AuthenticatorGetInfo;
    };

    inline void to_json(json& j, const MetadataStatementType& metadataStatement) {

        j = json{};

        if (metadataStatement.LegalHeader) {
            j["legalHeader"] = metadataStatement.LegalHeader.value();
        }

        if (metadataStatement.Aaid) {
            j["aaid"] = metadataStatement.Aaid.value();
        }

        if (metadataStatement.AaGUID) {
            j["aaguid"] = metadataStatement.AaGUID.value();
        }

        if (metadataStatement.AttestationCertificateKeyIdentifiers) {
            j["attestationCertificateKeyIdentifiers"] = metadataStatement.AttestationCertificateKeyIdentifiers.value();
        }

        j["description"] = metadataStatement.Description;

        if (metadataStatement.AlternativeDescriptions) {
            j["alternativeDescriptions"] = metadataStatement.AlternativeDescriptions.value();
        }

        j["authenticatorVersion"] = metadataStatement.AuthenticatorVersion;
        j["protocolFamily"] = metadataStatement.ProtocolFamily;
        j["schema"] = metadataStatement.Schema;
        j["upv"] = metadataStatement.Upv;
        j["authenticationAlgorithms"] = metadataStatement.AuthenticationAlgorithms;
        j["publicKeyAlgAndEncodings"] = metadataStatement.PublicKeyAlgAndEncodings;
        j["attestationTypes"] = metadataStatement.AttestationTypes;
        j["userVerificationDetails"] = metadataStatement.UserVerificationDetails;
        j["keyProtection"] = metadataStatement.KeyProtection;

        if (metadataStatement.IsKeyRestricted) {
            j["isKeyRestricted"] = metadataStatement.IsKeyRestricted.value();
        }

        if (metadataStatement.IsFreshUserVerificationRequired) {
            j["isFreshUserVerificationRequired"] = metadataStatement.IsFreshUserVerificationRequired.value();
        }

        j["matcherProtection"] = metadataStatement.MatcherProtection;

        if (metadataStatement.CryptoStrength) {
            j["cryptoStrength"] = metadataStatement.CryptoStrength.value();
        }

        if (metadataStatement.AttachmentHint) {
            j["attachmentHint"] = metadataStatement.AttachmentHint.value();
        }

        j["tcDisplay"] = metadataStatement.TcDisplay;

        if (metadataStatement.TcDisplayContentType) {
            j["tcDisplayContentType"] = metadataStatement.TcDisplayContentType.value();
        }

        if (metadataStatement.TcDisplayPNGCharacteristics) {
            j["tcDisplayPNGCharacteristics"] = metadataStatement.TcDisplayPNGCharacteristics.value();
        }

        j["attestationRootCertificates"] = metadataStatement.AttestationRootCertificates;

        if (metadataStatement.EcdaaTrustAnchors) {
            j["ecdaaTrustAnchors"] = metadataStatement.EcdaaTrustAnchors.value();
        }

        if (metadataStatement.Icon) {
            j["icon"] = metadataStatement.Icon.value();
        }

        if (metadataStatement.SupportedExtensions) {
            j["supportedExtensions"] = metadataStatement.SupportedExtensions.value();
        }

        if (metadataStatement.AuthenticatorGetInfo) {
            j["authenticatorGetInfo"] = metadataStatement.AuthenticatorGetInfo.value();
        }
    }

    inline void from_json(const json& j, MetadataStatementType& metadataStatement) {

        j.at("description").get_to(metadataStatement.Description);
        j.at("authenticatorVersion").get_to(metadataStatement.AuthenticatorVersion);
        j.at("protocolFamily").get_to(metadataStatement.ProtocolFamily);
        j.at("schema").get_to(metadataStatement.Schema);
        j.at("upv").get_to(metadataStatement.Upv);
        j.at("authenticationAlgorithms").get_to(metadataStatement.AuthenticationAlgorithms);
        j.at("publicKeyAlgAndEncodings").get_to(metadataStatement.PublicKeyAlgAndEncodings);
        j.at("attestationTypes").get_to(metadataStatement.AttestationTypes);
        j.at("userVerificationDetails").get_to(metadataStatement.UserVerificationDetails);
        j.at("keyProtection").get_to(metadataStatement.KeyProtection);
        j.at("matcherProtection").get_to(metadataStatement.MatcherProtection);
        j.at("tcDisplay").get_to(metadataStatement.TcDisplay);
        j.at("attestationRootCertificates").get_to(metadataStatement.AttestationRootCertificates);

        if (j.find("legalHeader") != j.end()) {
            metadataStatement.LegalHeader.emplace(j["legalHeader"].get<std::string>());
        }

        if (j.find("aaid") != j.end()) {
            metadataStatement.Aaid.emplace(j["aaid"].get<std::string>());
        }

        if (j.find("aaguid") != j.end()) {
            metadataStatement.AaGUID.emplace(j["aaguid"].get<std::string>());
        }

        if (j.find("attestationCertificateKeyIdentifiers") != j.end()) {
            metadataStatement.AttestationCertificateKeyIdentifiers.emplace(j["attestationCertificateKeyIdentifiers"].get<std::vector<std::string>>());
        }

        if (j.find("alternativeDescriptions") != j.end()) {
            metadataStatement.AlternativeDescriptions.emplace(j["alternativeDescriptions"].get<std::map<std::string, std::string>>());
        }

        if (j.find("isKeyRestricted") != j.end()) {
            metadataStatement.IsKeyRestricted.emplace(j["isKeyRestricted"].get<bool>());
        }

        if (j.find("isFreshUserVerificationRequired") != j.end()) {
            metadataStatement.IsFreshUserVerificationRequired.emplace(j["isFreshUserVerificationRequired"].get<bool>());
        }

        if (j.find("cryptoStrength") != j.end()) {
            metadataStatement.CryptoStrength.emplace(j["cryptoStrength"].get<uint16_t>());
        }

        if (j.find("attachmentHint") != j.end()) {
            metadataStatement.AttachmentHint.emplace(j["attachmentHint"].get<std::vector<std::string>>());
        }

        if (j.find("tcDisplayContentType") != j.end()) {
            metadataStatement.TcDisplayContentType.emplace(j["tcDisplayContentType"].get<std::string>());
        }

        if (j.find("tcDisplayPNGCharacteristics") != j.end()) {
            metadataStatement.TcDisplayPNGCharacteristics.emplace(j["tcDisplayPNGCharacteristics"].get<std::vector<DisplayPNGCharacteristicsDescriptorType>>());
        }

        if (j.find("ecdaaTrustAnchors") != j.end()) {
            metadataStatement.EcdaaTrustAnchors.emplace(j["ecdaaTrustAnchors"].get<std::vector<EcdaaTrustAnchorType>>());
        }

        if (j.find("icon") != j.end()) {
            metadataStatement.Icon.emplace(j["icon"].get<std::string>());
        }

        if (j.find("supportedExtensions") != j.end()) {
            metadataStatement.SupportedExtensions.emplace(j["supportedExtensions"].get<std::vector<ExtensionDescriptorType>>());
        }

        if (j.find("authenticatorGetInfo") != j.end()) {
            metadataStatement.AuthenticatorGetInfo.emplace(j["authenticatorGetInfo"].get<AuthenticatorGetInfoType>());
        }
    }

    // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary
    // BiometricStatusReportType - Contains the current BiometricStatusReport of one of the authenticator's biometric component.
    struct BiometricStatusReportType {

        BiometricStatusReportType() noexcept = default;

        BiometricStatusReportType(const json& j) :
            CertLevel(j["certLevel"].get<uint16_t>()),
            Modality(j["modality"].get<std::string>()) {

            if (j.find("effectiveDate") != j.end()) {
                EffectiveDate.emplace(j["effectiveDate"].get<std::string>());
            }

            if (j.find("certificationDescriptor") != j.end()) {
                CertificationDescriptor.emplace(j["certificationDescriptor"].get<std::string>());
            }

            if (j.find("certificateNumber") != j.end()) {
                CertificateNumber.emplace(j["certificateNumber"].get<std::string>());
            }

            if (j.find("certificationPolicyVersion") != j.end()) {
                CertificationPolicyVersion.emplace(j["certificationPolicyVersion"].get<std::string>());
            }

            if (j.find("certificationRequirementsVersion") != j.end()) {
                CertificationRequirementsVersion.emplace(j["certificationRequirementsVersion"].get<std::string>());
            }
        }

        BiometricStatusReportType(const BiometricStatusReportType& biometricStatusReport) noexcept = default;
        BiometricStatusReportType(BiometricStatusReportType&& biometricStatusReport) noexcept = default;
        ~BiometricStatusReportType() noexcept = default;

        BiometricStatusReportType& operator =(const BiometricStatusReportType& other) noexcept = default;
        BiometricStatusReportType& operator =(BiometricStatusReportType&& other) noexcept = default;

        // Achieved level of the biometric certification of this biometric component of the authenticator
        uint16_t CertLevel;
        // A single USER_VERIFY constant indicating the modality of the biometric component
        std::string Modality;
        // ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.
        std::optional<std::string> EffectiveDate;
        // Describes the externally visible aspects of the Biometric Certification evaluation.
        std::optional<std::string> CertificationDescriptor;
        // The unique identifier for the issued Biometric Certification.
        std::optional<std::string> CertificateNumber;
        // The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
        std::optional<std::string> CertificationPolicyVersion;
        // The version of the Biometric Requirements [FIDOBiometricsRequirements] the implementation is certified to, e.g. "1.0.0".
        std::optional<std::string> CertificationRequirementsVersion;
    };

    inline void to_json(json& j, const BiometricStatusReportType& biometricStatusReport) {

        j = json{
            { "certLevel", biometricStatusReport.CertLevel },
            { "modality",   biometricStatusReport.Modality }
        };

        if (biometricStatusReport.EffectiveDate) {
            j["effectiveDate"] = biometricStatusReport.EffectiveDate.value();
        }

        if (biometricStatusReport.CertificationDescriptor) {
            j["certificationDescriptor"] = biometricStatusReport.CertificationDescriptor.value();
        }

        if (biometricStatusReport.CertificateNumber) {
            j["certificateNumber"] = biometricStatusReport.CertificateNumber.value();
        }

        if (biometricStatusReport.CertificationPolicyVersion) {
            j["certificationPolicyVersion"] = biometricStatusReport.CertificationPolicyVersion.value();
        }

        if (biometricStatusReport.CertificationRequirementsVersion) {
            j["certificationRequirementsVersion"] = biometricStatusReport.CertificationRequirementsVersion.value();
        }
    }

    inline void from_json(const json& j, BiometricStatusReportType& biometricStatusReport) {

        j.at("certLevel").get_to(biometricStatusReport.CertLevel);
        j.at("modality").get_to(biometricStatusReport.Modality);

        if (j.find("effectiveDate") != j.end()) {
            biometricStatusReport.EffectiveDate.emplace(j["effectiveDate"].get<std::string>());
        }

        if (j.find("certificationDescriptor") != j.end()) {
            biometricStatusReport.CertificationDescriptor.emplace(j["certificationDescriptor"].get<std::string>());
        }

        if (j.find("certificateNumber") != j.end()) {
            biometricStatusReport.CertificateNumber.emplace(j["certificateNumber"].get<std::string>());
        }

        if (j.find("certificationPolicyVersion") != j.end()) {
            biometricStatusReport.CertificationPolicyVersion.emplace(j["certificationPolicyVersion"].get<std::string>());
        }

        if (j.find("certificationRequirementsVersion") != j.end()) {
            biometricStatusReport.CertificationRequirementsVersion.emplace(j["certificationRequirementsVersion"].get<std::string>());
        }
    }

    // StatusReportType - Contains the current BiometricStatusReport of one of the authenticator's biometric component.
    // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary
    struct StatusReportType {

        StatusReportType() noexcept = default;

        StatusReportType(const json& j) :
            Status(j["status"].get<AuthenticatorStatusType>()) {

            if (j.find("effectiveDate") != j.end()) {
                EffectiveDate.emplace(j["effectiveDate"].get<std::string>());
            }

            if (j.find("authenticatorVersion") != j.end()) {
                AuthenticatorVersion.emplace(j["authenticatorVersion"].get<uint32_t>());
            }

            if (j.find("certificate") != j.end()) {
                Certificate.emplace(j["certificate"].get<std::string>());
            }

            if (j.find("url") != j.end()) {
                URL.emplace(j["url"].get<std::string>());
            }

            if (j.find("certificationDescriptor") != j.end()) {
                CertificationDescriptor.emplace(j["certificationDescriptor"].get<std::string>());
            }

            if (j.find("certificateNumber") != j.end()) {
                CertificateNumber.emplace(j["certificateNumber"].get<std::string>());
            }

            if (j.find("certificationPolicyVersion") != j.end()) {
                CertificationPolicyVersion.emplace(j["certificationPolicyVersion"].get<std::string>());
            }

            if (j.find("certificationRequirementsVersion") != j.end()) {
                CertificationRequirementsVersion.emplace(j["certificationRequirementsVersion"].get<std::string>());
            }
        }

        StatusReportType(const StatusReportType& statusReport) noexcept = default;
        StatusReportType(StatusReportType&& statusReport) noexcept = default;
        ~StatusReportType() noexcept = default;

        StatusReportType& operator =(const StatusReportType& other) noexcept = default;
        StatusReportType& operator =(StatusReportType&& other) noexcept = default;

        // Status of the authenticator. Additional fields MAY be set depending on this value.
        AuthenticatorStatusType Status;
        // ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
        std::optional<std::string> EffectiveDate;
        // The authenticatorVersion that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.
        std::optional<uint32_t> AuthenticatorVersion;
        // Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008] PKIX certificate value related to the current status, if applicable.
        std::optional<std::string> Certificate;
        // HTTPS URL where additional information may be found related to the current status, if applicable.
        std::optional<std::string> URL;
        // Describes the externally visible aspects of the Authenticator Certification evaluation.
        std::optional<std::string> CertificationDescriptor;
        // The unique identifier for the issued Certification.
        std::optional<std::string> CertificateNumber;
        // The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
        std::optional<std::string> CertificationPolicyVersion;
        // The Document Version of the Authenticator Security Requirements (DV) [FIDOAuthenticatorSecurityRequirements] the implementation is certified to, e.g. "1.2.0".
        std::optional<std::string> CertificationRequirementsVersion;
    };

    inline void to_json(json& j, const StatusReportType& statusReport) {

        j = json{
            { "status", statusReport.Status }
        };

        if (statusReport.EffectiveDate) {
            j["effectiveDate"] = statusReport.EffectiveDate.value();
        }

        if (statusReport.AuthenticatorVersion) {
            j["authenticatorVersion"] = statusReport.AuthenticatorVersion.value();
        }

        if (statusReport.Certificate) {
            j["certificate"] = statusReport.Certificate.value();
        }

        if (statusReport.URL) {
            j["url"] = statusReport.URL.value();
        }

        if (statusReport.CertificationDescriptor) {
            j["certificationDescriptor"] = statusReport.CertificationDescriptor.value();
        }

        if (statusReport.CertificateNumber) {
            j["certificateNumber"] = statusReport.CertificateNumber.value();
        }

        if (statusReport.CertificationPolicyVersion) {
            j["certificationPolicyVersion"] = statusReport.CertificationPolicyVersion.value();
        }

        if (statusReport.CertificationRequirementsVersion) {
            j["certificationRequirementsVersion"] = statusReport.CertificationRequirementsVersion.value();
        }
    }

    inline void from_json(const json& j, StatusReportType& statusReport) {

        j.at("status").get_to(statusReport.Status);

        if (j.find("effectiveDate") != j.end()) {
            statusReport.EffectiveDate.emplace(j["effectiveDate"].get<std::string>());
        }

        if (j.find("authenticatorVersion") != j.end()) {
            statusReport.AuthenticatorVersion.emplace(j["authenticatorVersion"].get<uint32_t>());
        }

        if (j.find("certificate") != j.end()) {
            statusReport.Certificate.emplace(j["certificate"].get<std::string>());
        }

        if (j.find("url") != j.end()) {
            statusReport.URL.emplace(j["url"].get<std::string>());
        }

        if (j.find("certificationDescriptor") != j.end()) {
            statusReport.CertificationDescriptor.emplace(j["certificationDescriptor"].get<std::string>());
        }

        if (j.find("certificateNumber") != j.end()) {
            statusReport.CertificateNumber.emplace(j["certificateNumber"].get<std::string>());
        }

        if (j.find("certificationPolicyVersion") != j.end()) {
            statusReport.CertificationPolicyVersion.emplace(j["certificationPolicyVersion"].get<std::string>());
        }

        if (j.find("certificationRequirementsVersion") != j.end()) {
            statusReport.CertificationRequirementsVersion.emplace(j["certificationRequirementsVersion"].get<std::string>());
        }
    }

    // MetadataBLOBPayloadEntryType - Represents the MetadataBLOBPayloadEntry
    // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
    struct MetadataBLOBPayloadEntryType {

        MetadataBLOBPayloadEntryType() noexcept = default;

        MetadataBLOBPayloadEntryType(const json& j) :
            StatusReports(j["statusReports"].get<std::vector<StatusReportType>>()),
            TimeOfLastStatusChange(j["timeOfLastStatusChange"].get<std::string>()) {

            if (j.find("aaid") != j.end()) {
                Aaid.emplace(j["aaid"].get<std::string>());
            }

            if (j.find("aaguid") != j.end()) {
                AaGUID.emplace(j["aaguid"].get<std::string>());
            }

            if (j.find("attestationCertificateKeyIdentifiers") != j.end()) {
                AttestationCertificateKeyIdentifiers.emplace(j["attestationCertificateKeyIdentifiers"].get<std::vector<std::string>>());
            }

            if (j.find("metadataStatement") != j.end()) {
                MetadataStatement.emplace(j["metadataStatement"].get<MetadataStatementType>());
            }

            if (j.find("biometricStatusReports") != j.end()) {
                BiometricStatusReports.emplace(j["biometricStatusReports"].get<std::vector<BiometricStatusReportType>>());
            }

            if (j.find("rogueListURL") != j.end()) {
                RogueListURL.emplace(j["rogueListURL"].get<std::string>());
            }

            if (j.find("rogueListHash") != j.end()) {
                RogueListHash.emplace(j["rogueListHash"].get<std::string>());
            }
        }

        MetadataBLOBPayloadEntryType(const MetadataBLOBPayloadEntryType& metadataBLOBPayloadEntry) noexcept = default;
        MetadataBLOBPayloadEntryType(MetadataBLOBPayloadEntryType&& metadataBLOBPayloadEntry) noexcept = default;
        ~MetadataBLOBPayloadEntryType() noexcept = default;

        MetadataBLOBPayloadEntryType& operator =(const MetadataBLOBPayloadEntryType& other) noexcept = default;
        MetadataBLOBPayloadEntryType& operator =(MetadataBLOBPayloadEntryType&& other) noexcept = default;

        // The Authenticator Attestation ID.
        std::optional<std::string> Aaid;
        // The Authenticator Attestation GUID.
        std::optional<std::string> AaGUID;
        // A list of the attestation certificate public key identifiers encoded as hex string.
        std::optional<std::vector<std::string>> AttestationCertificateKeyIdentifiers;
        // The metadataStatement JSON object as defined in FIDOMetadataStatement.
        std::optional<MetadataStatementType> MetadataStatement;
        // Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator.
        std::optional<std::vector<BiometricStatusReportType>> BiometricStatusReports;
        // An array of status reports applicable to this authenticator.
        std::vector<StatusReportType> StatusReports;
        // ISO-8601 formatted date since when the status report array was set to the current value.
        std::string TimeOfLastStatusChange;
        // URL of a list of rogue (i.e. untrusted) individual authenticators.
        std::optional<std::string> RogueListURL;
        // The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]).
        std::optional<std::string> RogueListHash;
    };

    inline void to_json(json& j, const MetadataBLOBPayloadEntryType& metadataBLOBPayloadEntry) {

        j = json{};

        if (metadataBLOBPayloadEntry.Aaid) {
            j["aaid"] = metadataBLOBPayloadEntry.Aaid.value();
        }

        if (metadataBLOBPayloadEntry.AaGUID) {
            j["aaguid"] = metadataBLOBPayloadEntry.AaGUID.value();
        }

        if (metadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers) {
            j["attestationCertificateKeyIdentifiers"] = metadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers.value();
        }

        if (metadataBLOBPayloadEntry.MetadataStatement) {
            j["metadataStatement"] = metadataBLOBPayloadEntry.MetadataStatement.value();
        }

        if (metadataBLOBPayloadEntry.BiometricStatusReports) {
            j["biometricStatusReports"] = metadataBLOBPayloadEntry.BiometricStatusReports.value();
        }

        j["statusReports"] = metadataBLOBPayloadEntry.StatusReports;
        j["timeOfLastStatusChange"] = metadataBLOBPayloadEntry.TimeOfLastStatusChange;

        if (metadataBLOBPayloadEntry.RogueListURL) {
            j["rogueListURL"] = metadataBLOBPayloadEntry.RogueListURL.value();
        }

        if (metadataBLOBPayloadEntry.RogueListHash) {
            j["rogueListHash"] = metadataBLOBPayloadEntry.RogueListHash.value();
        }
    }

    inline void from_json(const json& j, MetadataBLOBPayloadEntryType& metadataBLOBPayloadEntry) {

        j.at("statusReports").get_to(metadataBLOBPayloadEntry.StatusReports);
        j.at("timeOfLastStatusChange").get_to(metadataBLOBPayloadEntry.TimeOfLastStatusChange);

        if (j.find("aaid") != j.end()) {
            metadataBLOBPayloadEntry.Aaid.emplace(j["aaid"].get<std::string>());
        }

        if (j.find("aaguid") != j.end()) {
            metadataBLOBPayloadEntry.AaGUID.emplace(j["aaguid"].get<std::string>());
        }

        if (j.find("attestationCertificateKeyIdentifiers") != j.end()) {
            metadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers.emplace(j["attestationCertificateKeyIdentifiers"].get<std::vector<std::string>>());
        }

        if (j.find("metadataStatement") != j.end()) {
            metadataBLOBPayloadEntry.MetadataStatement.emplace(j["metadataStatement"].get<MetadataStatementType>());
        }

        if (j.find("biometricStatusReports") != j.end()) {
            metadataBLOBPayloadEntry.BiometricStatusReports.emplace(j["biometricStatusReports"].get<std::vector<BiometricStatusReportType>>());
        }

        if (j.find("rogueListURL") != j.end()) {
            metadataBLOBPayloadEntry.RogueListURL.emplace(j["rogueListURL"].get<std::string>());
        }

        if (j.find("rogueListHash") != j.end()) {
            metadataBLOBPayloadEntry.RogueListHash.emplace(j["rogueListHash"].get<std::string>());
        }
    }

    // MetadataBLOBPayloadType - Represents the MetadataBLOBPayload
    struct MetadataBLOBPayloadType {

        MetadataBLOBPayloadType() noexcept = default;

        MetadataBLOBPayloadType(const json& j) :
            Number(j["no"].get<int64_t>()),
            NextUpdate(j["nextUpdate"].get<std::string>()),
            Entries(j["entries"].get<std::vector<MetadataBLOBPayloadEntryType>>()) {

            if (j.find("legalHeader") != j.end()) {
                LegalHeader.emplace(j["legalHeader"].get<std::string>());
            }
        }

        MetadataBLOBPayloadType(const MetadataBLOBPayloadType& metadataBLOBPayload) noexcept = default;
        MetadataBLOBPayloadType(MetadataBLOBPayloadType&& metadataBLOBPayload) noexcept = default;
        ~MetadataBLOBPayloadType() noexcept = default;

        MetadataBLOBPayloadType& operator =(const MetadataBLOBPayloadType& other) noexcept = default;
        MetadataBLOBPayloadType& operator =(MetadataBLOBPayloadType&& other) noexcept = default;

        // The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement.
        std::optional<std::string> LegalHeader;
        // The serial number of this UAF Metadata TOC Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor TOC will have a no value exactly incremented by one.
        int64_t Number;
        // ISO-8601 formatted date when the next update will be provided at latest.
        std::string NextUpdate;
        // List of zero or more MetadataTOCPayloadEntry objects.
        std::vector<MetadataBLOBPayloadEntryType> Entries;
    };

    inline void to_json(json& j, const MetadataBLOBPayloadType& metadataBLOBPayload) {

        j = json{};

        if (metadataBLOBPayload.LegalHeader) {
            j["legalHeader"] = metadataBLOBPayload.LegalHeader.value();
        }

        j["no"] = metadataBLOBPayload.Number;
        j["nextUpdate"] = metadataBLOBPayload.NextUpdate;
        j["entries"] = metadataBLOBPayload.Entries;
    }

    inline void from_json(const json& j, MetadataBLOBPayloadType& metadataBLOBPayload) {

        j.at("no").get_to(metadataBLOBPayload.Number);
        j.at("nextUpdate").get_to(metadataBLOBPayload.NextUpdate);
        j.at("entries").get_to(metadataBLOBPayload.Entries);

        if (j.find("legalHeader") != j.end()) {
            metadataBLOBPayload.LegalHeader.emplace(j["legalHeader"].get<std::string>());
        }
    }

    // METADATA is a map of authenticator AAGUIDs to corresponding metadata statements
    inline std::map<uuid_t, MetadataBLOBPayloadEntryType> METADATA{};

    // MDSGetEndpointsRequestType is the request sent to the conformance metadata getEndpoints endpoint.
    struct MDSGetEndpointsRequestType {

        MDSGetEndpointsRequestType() noexcept = default;

        MDSGetEndpointsRequestType(const json& j) :
            Endpoint(j["endpoint"].get<std::string>()) {
        }

        MDSGetEndpointsRequestType(const MDSGetEndpointsRequestType& mdsGetEndpointsRequest) noexcept = default;
        MDSGetEndpointsRequestType(MDSGetEndpointsRequestType&& mdsGetEndpointsRequest) noexcept = default;
        ~MDSGetEndpointsRequestType() noexcept = default;

        MDSGetEndpointsRequestType& operator =(const MDSGetEndpointsRequestType& other) noexcept = default;
        MDSGetEndpointsRequestType& operator =(MDSGetEndpointsRequestType&& other) noexcept = default;

        // The URL of the local server endpoint, e.g. https://webauthn.io/
        std::string Endpoint;
    };

    inline void to_json(json& j, const MDSGetEndpointsRequestType& mdsGetEndpointsRequest) {

        j = json{
            { "endpoint", mdsGetEndpointsRequest.Endpoint },
        };
    }

    inline void from_json(const json& j, MDSGetEndpointsRequestType& mdsGetEndpointsRequest) {

        j.at("endpoint").get_to(mdsGetEndpointsRequest.Endpoint);
    }

    // MDSGetEndpointsResponseType is the response received from a conformance metadata getEndpoints request.
    struct MDSGetEndpointsResponseType {

        MDSGetEndpointsResponseType() noexcept = default;

        MDSGetEndpointsResponseType(const json& j) :
            Status(j["status"].get<std::string>()),
            Result(j["result"].get<std::vector<std::string>>()) {
        }

        MDSGetEndpointsResponseType(const MDSGetEndpointsResponseType& mdsGetEndpointsResponse) noexcept = default;
        MDSGetEndpointsResponseType(MDSGetEndpointsResponseType&& mdsGetEndpointsResponse) noexcept = default;
        ~MDSGetEndpointsResponseType() noexcept = default;

        MDSGetEndpointsResponseType& operator =(const MDSGetEndpointsResponseType& other) noexcept = default;
        MDSGetEndpointsResponseType& operator =(MDSGetEndpointsResponseType&& other) noexcept = default;

        // The status of the response.
        std::string Status;
        // An array of urls, each pointing to a MetadataTOCPayload.
        std::vector<std::string> Result;
    };

    inline void to_json(json& j, const MDSGetEndpointsResponseType& mdsGetEndpointsResponse) {

        j = json{
            { "status", mdsGetEndpointsResponse.Status },
            { "result", mdsGetEndpointsResponse.Result }
        };
    }

    inline void from_json(const json& j, MDSGetEndpointsResponseType& mdsGetEndpointsResponse) {

        j.at("status").get_to(mdsGetEndpointsResponse.Status);
        j.at("result").get_to(mdsGetEndpointsResponse.Result);
    }

    // Metadata Errors

    struct MetadataError : public ErrorType {

        MetadataError() noexcept :
            ErrorType("metadata_error", "Metadata error") {
        }

        MetadataError(std::string&& type, std::string&& details) noexcept :
            ErrorType(
                std::move(type),
                std::move(details)) {
        }
    };

    struct ErrIntermediateCertRevoked : public MetadataError {

        ErrIntermediateCertRevoked() noexcept :
            MetadataError(
                "intermediate_revoked",
                "Intermediate certificate is on issuers revocation list") {
        }
    };

    struct ErrLeafCertRevoked : public MetadataError {

        ErrLeafCertRevoked() noexcept :
            MetadataError(
                "leaf_revoked",
                "Leaf certificate is on issuers revocation list") {
        }
    };

    struct ErrCRLUnavailable : public MetadataError {

        ErrCRLUnavailable() noexcept :
            MetadataError(
                "crl_unavailable",
                "Certificate revocation list is unavailable") {
        }
    };

    // Functions

    /*inline expected<bool> ValidateChain(const std::vector<std::any>& chain, c http.Client) noexcept {
        oRoot := make([]byte, base64.StdEncoding.DecodedLen(len(MDSRoot)))

        nRoot, err := base64.StdEncoding.Decode(oRoot, []byte(MDSRoot))
        if err != nil {
            return false, err
        }

        rootcert, err := x509.ParseCertificate(oRoot[:nRoot])
        if err != nil {
            return false, err
        }

        roots := x509.NewCertPool()

        roots.AddCert(rootcert)

        o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[1].(string))))

        n, err := base64.StdEncoding.Decode(o, []byte(chain[1].(string)))
        if err != nil {
            return false, err
        }

        intcert, err := x509.ParseCertificate(o[:n])
        if err != nil {
            return false, err
        }

        if revoked, ok := revoke.VerifyCertificate(intcert); !ok {
            issuer := intcert.IssuingCertificateURL

            if issuer != nil {
                return false, errCRLUnavailable
            }
        } else if revoked {
            return false, errIntermediateCertRevoked
        }

        ints := x509.NewCertPool()
        ints.AddCert(intcert)

        l := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

        n, err = base64.StdEncoding.Decode(l, []byte(chain[0].(string)))
        if err != nil {
            return false, err
        }

        leafcert, err := x509.ParseCertificate(l[:n])
        if err != nil {
            return false, err
        }

        if revoked, ok := revoke.VerifyCertificate(leafcert); !ok {
            return false, errCRLUnavailable
        } else if revoked {
            return false, errLeafCertRevoked
        }

        opts := x509.VerifyOptions{
            Roots:         roots,
            Intermediates: ints,
        }

        _, err = leafcert.Verify(opts)

        return err == nil, err
    }

    inline expected<MetadataBLOBPayloadType> UnmarshalMDSBLOB(const std::vector<uint8_t>& body, c http.Client) noexcept {
        var payload MetadataBLOBPayload

        token, err := jwt.Parse(string(body), func(token *jwt.Token) (interface{}, error) {
            // 2. If the x5u attribute is present in the JWT Header, then
            if _, ok := token.Header["x5u"].([]interface{}); ok {
                // never seen an x5u here, although it is in the spec
                return nil, errors.New("x5u encountered in header of metadata TOC payload")
            }
            var chain []interface{}
            // 3. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute.

            if x5c, ok := token.Header["x5c"].([]interface{}); !ok {
                // If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
                chain[0] = MDSRoot
            } else {
                chain = x5c
            }

            // The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor.
            valid, err := ValidateChain(chain, c)
            if !valid || err != nil {
                return nil, err
            }

            // Chain validated, extract the TOC signing certificate from the chain. Create a buffer large enough to hold the
            // certificate bytes.
            o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

            // base64 decode the certificate into the buffer.
            n, err := base64.StdEncoding.Decode(o, []byte(chain[0].(string)))
            if err != nil {
                return nil, err
            }

            // Parse the certificate from the buffer.
            cert, err := x509.ParseCertificate(o[:n])
            if err != nil {
                return nil, err
            }

            // 4. Verify the signature of the Metadata TOC object using the TOC signing certificate chain
            // jwt.Parse() uses the TOC signing certificate public key internally to verify the signature.
            return cert.PublicKey, err
        })

        if err != nil {
            return payload, err
        }

        err = mapstructure.Decode(token.Claims, &payload)

        return payload, err
    }*/
} // namespace WebAuthN::Metadata

#pragma GCC visibility pop

#endif /* WEBAUTHN_METADATA_IPP */
