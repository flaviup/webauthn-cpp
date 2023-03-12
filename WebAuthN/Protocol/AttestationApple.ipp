//
//  AttestationApple.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/12/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_APPLE_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_APPLE_IPP

#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/StringCompare.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;
    
    inline const std::string APPLE_ATTESTATION_KEY = "apple";

#pragma GCC visibility push(hidden)

    namespace {

        // Apple has not yet publish schema for the extension(as of JULY 2021.)
        struct AppleAnonymousAttestationType {

            std::vector<uint8_t> Nonce;// `asn1:"tag:1,explicit"`
        };

        // From §8.8. https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
        // The apple attestation statement looks like:
        // $$attStmtType //= (
        //
        //  fmt: "apple",
        //  attStmt: appleStmtFormat
        //
        // )
        //
        // appleStmtFormat = {
        //      x5c: [ credCert: bytes, * (caCert: bytes) ]
        // }
        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _VerifyAppleFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined
            // above and perform CBOR decoding on it to extract the contained fields.
            if (att.AttStatement) {
                
                auto atts = att.AttStatement.value();

                if (atts.find("x5c") == atts.cend()) { // If x5c is not present, return an error

                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving x5c value"));
                }
                auto x5c = atts["x5c"];

                if (x5c.empty()) {

                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }
                std::vector<uint8_t> attCertBytes{};

                try {

                    attCertBytes = x5c[0].get_binary();
                } catch (const std::exception&) {

                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }
                auto attCertResult = Util::Crypto::ParseCertificate(attCertBytes);

                if (!attCertResult) {

                    return unexpected(ErrAttestation().WithDetails(fmt::format("Error parsing certificate from ASN.1 data: {}", std::string(attCertResult.error()))));
                }
                auto attCert = attCertResult.value();

                // Step 2. Concatenate authenticatorData and clientDataHash to form nonceToHash.
                std::vector<uint8_t> nonceToHash(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(nonceToHash.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(nonceToHash.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());

                // Step 3. Perform SHA-256 hash of nonceToHash to produce nonce.
                auto nonce = Util::Crypto::SHA256(nonceToHash);

                // Step 4. Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
                constexpr auto ID_FIDO = "1.2.840.113635.100.8.2"; //asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2};
                std::vector<uint8_t> attExtBytes{};

                for (const auto& extension : attCert.Extensions) {

                    if (extension.ID == ID_FIDO) {

                        /*if (extension.IsCritical) {
                            
                            return unexpected(ErrInvalidAttestation().WithDetails("Attestation certificate FIDO extension marked as critical"));
                        }*/
                        attExtBytes = extension.Value;
                    }
                }

                if (attExtBytes.empty()) {

                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions missing 1.2.840.113635.100.8.2"));
                }
                AppleAnonymousAttestationType decoded{};

                /*if _, err = asn1.Unmarshal(attExtBytes, &decoded); err != nil {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to parse Apple attestation certificate extensions"));
                }*/

                if (!Util::StringCompare::ConstantTimeEqual(decoded.Nonce, nonce)) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Attestation certificate does not contain expected nonce"));
                }

                // Step 5. Verify that the credential public key equals the Subject Public Key of credCert.
                auto ok = WebAuthNCOSE::ParsePublicKey(att.AuthData.AttData.CredentialPublicKey);

                if (!ok) {

                    return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing the public key: {}\n", std::string(ok.error()))));
                }
                auto pubKey = ok.value();
                std::optional<ErrorType> err = std::nullopt;

                try {
                
                    auto credKey = std::any_cast<const WebAuthNCOSE::EC2PublicKeyDataType&>(pubKey);
                    auto attCertPubKeyResult = Util::Crypto::ParseCertificatePublicKey(attCertBytes);

                    if (!attCertPubKeyResult) {
                        err = ErrInvalidAttestation().WithDetails(fmt::format("Error parsing certificate public key from ASN.1 data: {}", std::string(attCertPubKeyResult.error())));
                    } else {
                        
                        ok = WebAuthNCOSE::ParsePublicKey(std::vector<uint8_t>(attCertPubKeyResult.value().data(), attCertPubKeyResult.value().data() + attCertPubKeyResult.value().size()));

                        if (!ok) {

                            return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing the public key: {}\n", std::string(ok.error()))));
                        }
                        auto subjectKey = std::any_cast<const WebAuthNCOSE::EC2PublicKeyDataType&>(ok.value());

                        if (credKey != subjectKey) {
                            err = ErrInvalidAttestation().WithDetails("Certificate public key does not match public key in authData");
                        }
                    }
                } catch(const std::bad_any_cast&) {
                    err = ErrUnsupportedKey();
                }

                if (err) {
                    return unexpected(err.value());
                }

                // Step 6. If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
                return std::tuple{json(Metadata::AuthenticatorAttestationType::AnonCA).get<std::string>(), std::optional<json>{x5c}};
            } else {

                return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"));
            }
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterAppleAttestation() noexcept {

        RegisterAttestationFormat(APPLE_ATTESTATION_KEY, _VerifyAppleFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_APPLE_IPP
