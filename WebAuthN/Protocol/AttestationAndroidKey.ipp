//
//  AttestationAndroidKey.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/10/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_ANDROID_KEY_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_ANDROID_KEY_IPP

#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/StringCompare.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;
    
    inline const std::string ANDROID_KEY_ATTESTATION_KEY = "android-key";

#pragma GCC visibility push(hidden)

    namespace {

        /**
         * Possible purposes of a key (or pair).
         */
        enum class KmPurposeType : int {

            Encrypt,           /* Usable with RSA, EC and AES keys. */
            Decrypt,           /* Usable with RSA, EC and AES keys. */
            Sign,              /* Usable with RSA, EC and HMAC keys. */
            Verify,            /* Usable with RSA, EC and HMAC keys. */
            DeriveKey,         /* Usable with EC keys. */
            Wrap               /* Usable with wrapped keys. */
        };

        /**
         * The origin of a key (or pair), i.e. where it was generated.  Note that KM_TAG_ORIGIN can be found
         * in either the hardware-enforced or software-enforced list for a key, indicating whether the key
         * is hardware or software-based.  Specifically, a key with KM_ORIGIN_GENERATED in the
         * hardware-enforced list is guaranteed never to have existed outide the secure hardware.
         */
        enum class KmKeyOriginType : int {

            Generated,        /* Generated in keymaster.  Should not exist outside the TEE. */
            Derived,          /* Derived inside keymaster.  Likely exists off-device. */
            Imported,         /* Imported into keymaster.  Existed as clear text in Android. */
            Unknown           /* Keymaster did not record origin.  This value can only be seen on
            * keys in a keymaster0 implementation.  The keymaster0 adapter uses
            * this value to document the fact that it is unknown whether the key
            * was generated inside or imported into keymaster. */
        };

        enum class VerifiedBootStateType : int {

            Verified,
            SelfSigned,
            Unverified,
            Failed
        };

        struct RootOfTrustType {

            std::vector<uint8_t> VerifiedBootKey;
            bool IsDeviceLocked;
            VerifiedBootStateType VerifiedBootState;
            std::vector<uint8_t> VerifiedBootHash;
        };

        struct AuthorizationListType {

            std::optional<std::vector<int32_t>> Purpose;                     // `asn1:"tag:1,explicit,set,optional"`
            std::optional<int32_t>              Algorithm;                   // `asn1:"tag:2,explicit,optional"`
            std::optional<int32_t>              KeySize;                     // `asn1:"tag:3,explicit,optional"`
            std::optional<std::vector<int32_t>> Digest;                      // `asn1:"tag:5,explicit,set,optional"`
            std::optional<std::vector<int32_t>> Padding;                     // `asn1:"tag:6,explicit,set,optional"`
            std::optional<int32_t>              EcCurve;                     // `asn1:"tag:10,explicit,optional"`
            std::optional<int32_t>              RsaPublicExponent;           // `asn1:"tag:200,explicit,optional"`
            std::optional<json>                 RollbackResistance;          // `asn1:"tag:303,explicit,optional"`
            std::optional<int32_t>              ActiveDateTime;              // `asn1:"tag:400,explicit,optional"`
            std::optional<int32_t>              OriginationExpireDateTime;   // `asn1:"tag:401,explicit,optional"`
            std::optional<int32_t>              UsageExpireDateTime;         // `asn1:"tag:402,explicit,optional"`
            std::optional<json>                 NoAuthRequired;              // `asn1:"tag:503,explicit,optional"`
            std::optional<int32_t>              UserAuthType;                // `asn1:"tag:504,explicit,optional"`
            std::optional<int32_t>              AuthTimeout;                 // `asn1:"tag:505,explicit,optional"`
            std::optional<json>                 AllowWhileOnBody;            // `asn1:"tag:506,explicit,optional"`
            std::optional<json>                 TrustedUserPresenceRequired; // `asn1:"tag:507,explicit,optional"`
            std::optional<json>                 TrustedConfirmationRequired; // `asn1:"tag:508,explicit,optional"`
            std::optional<json>                 UnlockedDeviceRequired;      // `asn1:"tag:509,explicit,optional"`
            std::optional<json>                 AllApplications;             // `asn1:"tag:600,explicit,optional"`
            std::optional<json>                 ApplicationID;               // `asn1:"tag:601,explicit,optional"`
            std::optional<int32_t>              CreationDateTime;            // `asn1:"tag:701,explicit,optional"`
            std::optional<int32_t>              Origin;                      // `asn1:"tag:702,explicit,optional"`
            std::optional<RootOfTrustType>      RootOfTrust;                 // `asn1:"tag:704,explicit,optional"`
            std::optional<int32_t>              OsVersion;                   // `asn1:"tag:705,explicit,optional"`
            std::optional<int32_t>              OsPatchLevel;                // `asn1:"tag:706,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationApplicationID;    // `asn1:"tag:709,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDBrand;          // `asn1:"tag:710,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDDevice;         // `asn1:"tag:711,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDProduct;        // `asn1:"tag:712,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDSerial;         // `asn1:"tag:713,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDImei;           // `asn1:"tag:714,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDMeid;           // `asn1:"tag:715,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDManufacturer;   // `asn1:"tag:716,explicit,optional"`
            std::optional<std::vector<uint8_t>> AttestationIDModel;          // `asn1:"tag:717,explicit,optional"`
            std::optional<int32_t>              VendorPatchLevel;            // `asn1:"tag:718,explicit,optional"`
            std::optional<int32_t>              BootPatchLevel;              // `asn1:"tag:719,explicit,optional"`
        };

        struct KeyDescriptionType {

            int32_t               AttestationVersion;
            uint32_t              AttestationSecurityLevel; // asn1.Enumerated
            int32_t               KeymasterVersion;
            uint32_t              KeymasterSecurityLevel;   // asn1.Enumerated
            std::vector<uint8_t>  AttestationChallenge;
            std::vector<uint8_t>  UniqueID;
            AuthorizationListType SoftwareEnforced;
            AuthorizationListType TeeEnforced;
        };

        // From §8.4. https://www.w3.org/TR/webauthn/#android-key-attestation
        // The android-key attestation statement looks like:
        // $$attStmtType //= (
        //
        // fmt: "android-key",
        // attStmt: androidStmtFormat
        //
        // )
        //
        // androidStmtFormat = {
        // alg: COSEAlgorithmIdentifier,
        //      sig: bytes,
        //      x5c: [ credCert: bytes, * (caCert: bytes) ]
        //  }
        static inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _VerifyAndroidKeyFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:
            // §8.4.1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
            // the contained fields.

            // Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
            // used to generate the attestation signature.
            if (att.AttStatement) {
                
                auto atts = att.AttStatement.value();

                if (atts.find("alg") == atts.cend()) {

                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving alg value"));
                }
                auto alg = atts["alg"].get<int64_t>();

                // Get the sig value - A byte string containing the attestation signature.
                if (atts.find("sig") == atts.cend() || !atts["sig"].is_binary()) {

                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving sig value"));
                }
                auto signature = atts["sig"].get_binary();

                if (atts.find("x5c") == atts.cend()) { // If x5c is not present, return an error

                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving x5c value"));
                }
                auto x5c = atts["x5c"];

                // §8.4.2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
                // using the public key in the first certificate in x5c with the algorithm specified in alg.
                if (x5c.empty()) {

                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }
                std::vector<uint8_t> attCertBytes{};

                try {

                    attCertBytes = x5c[0].get_binary();
                } catch (const std::exception&) {

                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }
                std::vector<uint8_t> signatureData(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(signatureData.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(signatureData.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());
                auto attCertResult = Util::Crypto::ParseCertificate(attCertBytes);

                if (!attCertResult) {

                    return unexpected(ErrAttestation().WithDetails(fmt::format("Error parsing certificate from ASN.1 data: {}", std::string(attCertResult.error()))));
                }
                auto attCert = attCertResult.value();

                auto coseAlg = static_cast<WebAuthNCOSE::COSEAlgorithmIdentifierType>(alg);
                auto sigAlg = WebAuthNCOSE::SigAlgFromCOSEAlg(coseAlg);
                auto signatureCheckResult = Util::Crypto::CheckSignature(attCertBytes, 
                                                                        WebAuthNCOSE::SignatureAlgorithmTypeToString(sigAlg), 
                                                                        signatureData, 
                                                                        signature);

                if (!signatureCheckResult || !signatureCheckResult.value()) {

                    return unexpected(ErrInvalidAttestation().WithDetails(signatureCheckResult ? "Signature validation error" : fmt::format("Signature validation error: {}", std::string(signatureCheckResult.error()))));
                }

                // Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
                auto ok = WebAuthNCOSE::ParsePublicKey(att.AuthData.AttData.CredentialPublicKey);

                if (!ok) {

                    return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing the public key: {}\n", std::string(ok.error()))));
                }
                auto pubKey = ok.value();
                std::optional<ErrorType> err = std::nullopt;

                try {
                
                    auto key = std::any_cast<const WebAuthNCOSE::EC2PublicKeyDataType&>(pubKey);

                    auto verificationResult = key.Verify(signatureData, signature);

                    if (!verificationResult) {
                        err = verificationResult.error();
                    } else if (!verificationResult.value()) {
                        err = ErrInvalidAttestation().WithDetails("Signature verification failed");
                    }
                } catch(const std::bad_any_cast&) {
                    err = ErrUnsupportedKey();
                }
                /*auto success = false;
                auto vpk = WebAuthNCOSE::KeyCast(pubKey, success);

                if (success) {

                    auto verificationResult = vpk.Value.Verify(signatureData, signature);

                    if (!verificationResult) {
                        err = verificationResult.error();
                    } else if (!verificationResult.value()) {

                        return unexpected(ErrInvalidAttestation().WithDetails("Signature verification failed"));
                    }
                } else {
                    
                    err = ErrUnsupportedKey();
                }*/

                if (err) {

                    return unexpected(err.value());
                }

                constexpr auto ID_FIDO = "1.3.6.1.4.1.11129.2.1.17"; //asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17};
                std::vector<uint8_t> attExtBytes{};

                for (const auto& extension : attCert.Extensions) {

                    if (extension.ID == ID_FIDO) {

                        if (extension.IsCritical) {
                            
                            return unexpected(ErrInvalidAttestation().WithDetails("Attestation certificate FIDO extension marked as critical"));
                        }
                        attExtBytes = extension.Value;
                    }
                }

                if (attExtBytes.empty()) {

                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions missing 1.3.6.1.4.1.11129.2.1.17"));
                }

                // As noted in §8.4.1 (https://www.w3.org/TR/webauthn/#key-attstn-cert-requirements) the Android Key Attestation attestation certificate's
                // android key attestation certificate extension data is identified by the OID "1.3.6.1.4.1.11129.2.1.17".
                KeyDescriptionType decoded{};

                /*if _, err = asn1.Unmarshal(attExtBytes, &decoded); err != nil {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to parse Android key attestation certificate extensions"));
                }*/

                // Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
                if (!Util::StringCompare::ConstantTimeEqual(decoded.AttestationChallenge, clientDataHash)) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation challenge not equal to clientDataHash"));
                }

                // The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
                if (decoded.SoftwareEnforced.AllApplications || decoded.TeeEnforced.AllApplications) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions contains all applications field"));
                }

                // For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.
                // The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.  (which == 0)
                if ((decoded.SoftwareEnforced.Origin && decoded.SoftwareEnforced.Origin.value() != static_cast<int32_t>(KmKeyOriginType::Generated)) ||
                    (decoded.TeeEnforced.Origin && decoded.TeeEnforced.Origin.value() != static_cast<int32_t>(KmKeyOriginType::Generated)) ||
                    (!decoded.SoftwareEnforced.Origin && !decoded.TeeEnforced.Origin)) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions contains authorization list with origin not equal KM_ORIGIN_GENERATED"));
                }

                // The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN. (which == 2)
                if ((!decoded.SoftwareEnforced.Purpose || 
                     std::find(decoded.SoftwareEnforced.Purpose.value().cbegin(), 
                               decoded.SoftwareEnforced.Purpose.value().cend(), 
                               static_cast<int32_t>(KmPurposeType::Sign)) == decoded.SoftwareEnforced.Purpose.value().cend()) && 
                    (!decoded.TeeEnforced.Purpose || 
                     std::find(decoded.TeeEnforced.Purpose.value().cbegin(), 
                               decoded.TeeEnforced.Purpose.value().cend(), 
                               static_cast<int32_t>(KmPurposeType::Sign)) == decoded.TeeEnforced.Purpose.value().cend())) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions contains authorization list with purpose not equal KM_PURPOSE_SIGN"));
                }

                return std::tuple{json(Metadata::AuthenticatorAttestationType::BasicFull).get<std::string>(), std::optional<json>{x5c}};
            } else {

                return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"));
            }
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterAndroidKeyAttestation() noexcept {

        RegisterAttestationFormat(ANDROID_KEY_ATTESTATION_KEY, _VerifyAndroidKeyFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_ANDROID_KEY_IPP
