//
//  AttestationPacked.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/02/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_PACKED_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_PACKED_IPP

#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Metadata/Metadata.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/Time.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;
    
    inline const std::string PACKED_ATTESTATION_KEY = "packed";

#pragma GCC visibility push(hidden)

    namespace {

        // Handle the attestation steps laid out in
        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _HandleBasicAttestation(const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& clientDataHash,
                                const std::vector<uint8_t>& authData,
                                const std::vector<uint8_t>& aaguid,
                                const int64_t alg,
                                const json::array_t& x5c) noexcept {

            // Step 2.1. Verify that sig is a valid signature over the concatenation of authenticatorData
            // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.

            for (const auto& c : x5c) {

                std::vector<uint8_t> cb;

                try {

                    cb = c.get_binary();
                } catch (const std::exception&) {

                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }

                auto certParsingResult = Util::Crypto::ParseCertificate(cb);

                if (!certParsingResult) {

                    return unexpected(ErrAttestationFormat().
                        WithDetails(fmt::format("Error parsing certificate from ASN.1 data: {}", std::string(certParsingResult.error()))));
                }
                auto ct = certParsingResult.value();
                auto notBeforeResult = Util::Time::ParseISO8601(ct.NotBefore);
                auto notAfterResult = Util::Time::ParseISO8601(ct.NotAfter);

                if (!notBeforeResult || !notAfterResult) {

                    return unexpected(ErrAttestationFormat().WithDetails("Cert in chain has no valid date times"));
                }
                auto notBefore = notBeforeResult.value();
                auto notAfter = notAfterResult.value();
                auto now = Util::Time::Timestamp();

                if (notBefore > now || notAfter < now) {

                    return unexpected(ErrAttestationFormat().WithDetails("Cert in chain not time valid"));
                }
            }

            if (x5c.empty()) {

                return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
            }
            std::vector<uint8_t> attCertBytes{};

            try {

                attCertBytes = x5c[0].get_binary();
            } catch (const std::exception&) {

                return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
            }
            std::vector<uint8_t> signatureData(authData.size() + clientDataHash.size());
            std::memcpy(signatureData.data(), authData.data(), authData.size());
            std::memcpy(signatureData.data() + authData.size(), clientDataHash.data(), clientDataHash.size());
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

            // Step 2.2 Verify that attestnCert meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
            // §8.2.1 can be found here https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements

            // Step 2.2.1 (from §8.2.1) Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
            if (attCert.Version != 3) {

                return unexpected(ErrAttestationCertificate().WithDetails("Attestation Certificate is incorrect version"));
            }

            // Step 2.2.2 (from §8.2.1) Subject field MUST be set to:

            // 	Subject-C
            // 	ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)

            //  TODO: Find a good, useable, country code library. For now, check stringy-ness
            if (attCert.Subject.Country.empty()) {

                return unexpected(ErrAttestationCertificate().WithDetails("Attestation Certificate Country Code is invalid"));
            }

            // 	Subject-O
            // 	Legal name of the Authenticator vendor (UTF8String)
            if (attCert.Subject.Organization.empty()) {

                return unexpected(ErrAttestationCertificate().WithDetails("Attestation Certificate Organization is invalid"));
            }

            // 	Subject-OU
            // 	Literal string “Authenticator Attestation” (UTF8String)
            if (attCert.Subject.OrganizationalUnit != "Authenticator Attestation") {

                // TODO: Implement a return error when I'm more certain this is general practice
                //return unexpected(ErrAttestationCertificate().WithDetails("Attestation Certificate OrganizationalUnit is invalid"));
            }

            // 	Subject-CN
            //  A UTF8String of the vendor’s choosing
            if (attCert.Subject.CommonName.empty()) {

                return unexpected(ErrAttestationCertificate().WithDetails("Attestation Certificate Common Name is invalid"));
            }

            // TODO: And then what

            // Step 2.2.3 (from §8.2.1) If the related attestation root certificate is used for multiple authenticator models,
            // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the
            // AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
            constexpr auto ID_FIDO = "1.3.6.1.4.1.45724.1.1.4"; //asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4};
            std::vector<uint8_t> foundAAGUID{};

            for (const auto& extension : attCert.Extensions) {

                if (extension.ID == ID_FIDO) {

                    if (extension.IsCritical) {
                        
                        return unexpected(ErrInvalidAttestation().WithDetails("Attestation certificate FIDO extension marked as critical"));
                    }
                    foundAAGUID = extension.Value;
                }
            }

            // We validate the AAGUID as mentioned above
            // This is not well defined in§8.2.1 but mentioned in step 2.3: we validate the AAGUID if it is present within the certificate
            // and make sure it matches the auth data AAGUID
            // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING. Thus, the
            // AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
            if (!foundAAGUID.empty()) {

                //std::vector<uint8_t> unmarshalledAAGUID{};
                //asn1.Unmarshal(foundAAGUID, &unmarshalledAAGUID);

                //if (aaguid != unmarshalledAAGUID) {
                if (aaguid != foundAAGUID) {

                    return unexpected(ErrInvalidAttestation().WithDetails("Certificate AAGUID does not match Auth Data certificate"));
                }
            }

            // Step 2.2.4 The Basic Constraints extension MUST have the CA component set to false.
            if (attCert.IsCA) {

                return unexpected(ErrInvalidAttestation().WithDetails("Attestation certificate's Basic Constraints marked as CA"));
            }

            // Note for 2.2.5 An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL
            // Distribution Point extension [RFC5280](https://www.w3.org/TR/webauthn/#biblio-rfc5280) are
            // both OPTIONAL as the status of many attestation certificates is available through authenticator
            // metadata services. See, for example, the FIDO Metadata Service
            // [FIDOMetadataService] (https://www.w3.org/TR/webauthn/#biblio-fidometadataservice)

            // Step 2.4 If successful, return attestation type Basic and attestation trust path x5c.
            // We don't handle trust paths yet but we're done

            return std::tuple{json(Metadata::AuthenticatorAttestationType::BasicFull).get<std::string>(), std::optional<json>{x5c}};
        }

        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _HandleECDAAAttestation(const std::vector<uint8_t>& signature, 
                                const std::vector<uint8_t>& clientDataHash, 
                                const std::vector<uint8_t>& ecdaaKeyID) noexcept {

            return unexpected(ErrNotSpecImplemented());
        }

        inline std::optional<ErrorType>
        _VerifyKeyAlgorithm(const int64_t keyAlgorithm, const int64_t attestedAlgorithm) noexcept {
            
            if (keyAlgorithm != attestedAlgorithm) {

                return ErrInvalidAttestation().WithDetails("Public key algorithm does not equal att statement algorithm");
            }

            return std::nullopt;
        }

        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _HandleSelfAttestation(const int64_t alg,
                               const std::vector<uint8_t>& pubKey,
                               const std::vector<uint8_t>& authData,
                               const std::vector<uint8_t>& clientDataHash,
                               const std::vector<uint8_t>& signature) noexcept {

            // §4.1 Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.

            // §4.2 Verify that sig is a valid signature over the concatenation of authenticatorData and
            // clientDataHash using the credential public key with alg.
            std::vector<uint8_t> verificationData(authData.size() + clientDataHash.size());
            std::memcpy(verificationData.data(), authData.data(), authData.size());
            std::memcpy(verificationData.data() + authData.size(), clientDataHash.data(), clientDataHash.size());

            auto ok = WebAuthNCOSE::ParsePublicKey(pubKey);

            if (!ok) {

                return unexpected(ErrAttestationFormat().WithDetails(fmt::format("Error parsing the public key: {}\n", std::string(ok.error()))));
            }
            auto key = ok.value();
            std::optional<ErrorType> err = std::nullopt;
            auto success = false;
            auto vpk = WebAuthNCOSE::KeyCast(key, success);

            if (success) {

                err = _VerifyKeyAlgorithm(vpk.Value.Algorithm, alg);
            } else {
                
                err = ErrUnsupportedKey();
            }

            if (err) {

                return unexpected(err.value());
            }
            auto validationResult = WebAuthNCOSE::VerifySignature(key, verificationData, signature);

            if (validationResult && !validationResult.value()) {

                return unexpected(ErrInvalidAttestation().WithDetails("Unable to verify signature"));
            }

            if (!validationResult) {

                return unexpected(validationResult.error());
            }

            return std::tuple{json(Metadata::AuthenticatorAttestationType::BasicSurrogate).get<std::string>(), std::nullopt};
        }

        // The packed attestation statement looks like:
        //
        //	packedStmtFormat = {
        //	 	alg: COSEAlgorithmIdentifier,
        //	 	sig: bytes,
        //	 	x5c: [ attestnCert: bytes, * (caCert: bytes) ]
        //	 } OR
        //	 {
        //	 	alg: COSEAlgorithmIdentifier, (-260 for ED256 / -261 for ED512)
        //	 	sig: bytes,
        //	 	ecdaaKeyId: bytes
        //	 } OR
        //	 {
        //	 	alg: COSEAlgorithmIdentifier
        //	 	sig: bytes,
        //	 }
        //
        // Specification: §8.2. Packed Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-packed-attestation)
        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
        _VerifyPackedFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined
            // above and perform CBOR decoding on it to extract the contained fields.

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
                auto sig = atts["sig"].get_binary();

                // Step 2. If x5c is present, this indicates that the attestation type is not ECDAA.
                if (atts.find("x5c") != atts.cend()) {

                    auto x5c = atts["x5c"];

                    // Handle Basic Attestation steps for the x509 Certificate
                    return _HandleBasicAttestation(sig, clientDataHash, att.RawAuthData, att.AuthData.AttData.AAGUID, alg, x5c);
                }

                // Step 3. If ecdaaKeyId is present, then the attestation type is ECDAA.
                // Also make sure the we did not have an x509 then
                if (atts.find("ecdaaKeyId") != atts.cend()) {

                    auto ecdaaKeyID = atts["ecdaaKeyId"];
                    // Handle ECDAA Attestation steps for the x509 Certificate
                    return _HandleECDAAAttestation(sig, clientDataHash, ecdaaKeyID);
                }

                // Step 4. If neither x5c nor ecdaaKeyId is present, self attestation is in use.
                return _HandleSelfAttestation(alg, att.AuthData.AttData.CredentialPublicKey, att.RawAuthData, clientDataHash, sig);
            } else {

                return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided."));
            }
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterPackedAttestation() noexcept {

        RegisterAttestationFormat(PACKED_ATTESTATION_KEY, _VerifyPackedFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_PACKED_IPP
