//
//  AttestationU2F.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_U2F_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_U2F_IPP

#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Util/Crypto.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using namespace std::string_literals;
    using json = nlohmann::json;
    
    inline const std::string U2F_ATTESTATION_KEY = "fido-u2f";

#pragma GCC visibility push(hidden)

    namespace {

        // _VerifyU2FFormat - Follows verification steps set out by https://www.w3.org/TR/webauthn/#fido-u2f-attestation
        static inline expected<std::tuple<std::string, std::optional<json>>>
        _VerifyU2FFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            if (std::any_of(att.AuthData.AttData.AAGUID.cbegin(), 
                            att.AuthData.AttData.AAGUID.cend(),
                            [](const uint8_t& b) { return b != 0; })) {
                return unexpected(ErrUnsupportedAlgorithm().WithDetails("U2F attestation format AAGUID not set to 0x00"s));
            }
            auto attCertPubKeyResult = Util::Crypto::ParseCertificateECPublicKeyInfo(att.AuthData.AttData.CredentialPublicKey);

            if (!attCertPubKeyResult) {
                return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing certificate public key from ASN.1 data: {}", std::string(attCertPubKeyResult.error()))));
            }
            const auto& [algoNid, curveNid, xCoord, yCoord] = attCertPubKeyResult.value();
            auto algo = WebAuthNCOSE::COSEAlgorithmIdentifierTypeFromNID(algoNid);

            if (algo != WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256 &&
                algo != WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256K) {
                return unexpected(ErrUnsupportedAlgorithm().WithDetails("Non-ES256 Public Key algorithm used"));
            }

            // U2F Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined above
            // and perform CBOR decoding on it to extract the contained fields.

            // The Format/syntax is
            // u2fStmtFormat = {
            //      x5c: [ attestnCert: bytes ],
            //      sig: bytes
            // }

            // Check for "x5c" which is a single element array containing the attestation certificate in X.509 format.
            if (att.AttStatement) {

                auto atts = att.AttStatement.value();

                if (atts.find("x5c") == atts.cend()) { // If x5c is not present, return an error
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving x5c value"));
                }
                auto x5c = atts["x5c"];

                if (x5c.empty()) {
                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }

                // U2F Step 2. (1) Check that x5c has exactly one element and let attCert be that element. (2) Let certificate public
                // key be the public key conveyed by attCert. (3) If certificate public key is not an Elliptic Curve (EC) public
                // key over the P-256 curve, terminate this algorithm and return an appropriate error.

                // Step 2.1
                if (x5c.size() > 1) {
                    return unexpected(ErrAttestationFormat().WithDetails("Received more than one element in x5c values"));
                }

                // Check for "sig" which is The attestation signature. The signature was calculated over the (raw) U2F
                // registration response message https://www.w3.org/TR/webauthn/#biblio-fido-u2f-message-formats]
                // received by the client from the authenticator.
                if (atts.find("sig") == atts.cend() || !atts["sig"].is_binary()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving sig value"));
                }
                auto signature = atts["sig"].get_binary();
                
                // Note: Packed Attestation, FIDO U2F Attestation, and Assertion Signatures support ASN.1,but it is recommended
                // that any new attestation formats defined not use ASN.1 encodings, but instead represent signatures as equivalent
                // fixed-length byte arrays without internal structure, using the same representations as used by COSE signatures
                // as defined in RFC8152 (https://www.w3.org/TR/webauthn/#biblio-rfc8152)
                // and RFC8230 (https://www.w3.org/TR/webauthn/#biblio-rfc8230).

                // Step 2.2
                std::vector<uint8_t> attCertBytes{};

                try {
                    attCertBytes = x5c[0].get_binary();
                } catch (const std::exception&) {
                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"));
                }

                // Step 2.3
                attCertPubKeyResult = Util::Crypto::ParseCertificateECPublicKeyInfo(attCertBytes);

                if (!attCertPubKeyResult) {
                    return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing certificate public key from ASN.1 data: {}", std::string(attCertPubKeyResult.error()))));
                }
                const auto& [algoNid, curveNid, xCoord, yCoord] = attCertPubKeyResult.value();
                auto algo = WebAuthNCOSE::COSEAlgorithmIdentifierTypeFromNID(algoNid);
                auto curve = curveNid ? WebAuthNCOSE::COSEEllipticCurveTypeFromNID(curveNid.value()) : 
                                        std::nullopt;

                if (algo != WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256 &&
                    algo != WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256K &&
                    (!curve || curve.value() != WebAuthNCOSE::COSEEllipticCurveType::P256)) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate is in invalid format"));
                }

                // Step 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey
                // from authenticatorData.attestedCredentialData.

                auto rpIdHash = att.AuthData.RPIDHash;
                auto credentialID = att.AuthData.AttData.CredentialID;

                // credentialPublicKey handled earlier

                // Step 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of RFC8152 [https://www.w3.org/TR/webauthn/#biblio-rfc8152])
                // to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key
                // Representation Formats of FIDO-Registry [https://www.w3.org/TR/webauthn/#biblio-fido-registry]).

                // Let xCoord be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and confirm
                // its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and
                // return an appropriate error.

                // Let yCoord be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and confirm
                // its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and
                // return an appropriate error.

                if ((xCoord && xCoord.value().size() > 32) || (yCoord && yCoord.value().size() > 32)) {
                    return unexpected(ErrAttestation().WithDetails("X or Y Coordinate for key is invalid length"));
                }

                // Let publicKeyU2F be the concatenation 0x04 || x || y.
                std::vector<uint8_t> pubKeyData(1 + xCoord.value().size() + yCoord.value().size());
                pubKeyData[0] = static_cast<uint8_t>(0x04);
                std::memcpy(pubKeyData.data() + 1, xCoord.value().data(), xCoord.value().size());
                std::memcpy(pubKeyData.data() + xCoord.value().size() + 1, yCoord.value().data(), yCoord.value().size());

                // Step 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
                // (see §4.3 of FIDO-U2F-Message-Formats [https://www.w3.org/TR/webauthn/#biblio-fido-u2f-message-formats]).
                std::vector<uint8_t> verificationData(1 + rpIdHash.size() + clientDataHash.size() + credentialID.size() + pubKeyData.size());
                verificationData[0] = static_cast<uint8_t>(0x04);
                std::memcpy(verificationData.data() + 1, rpIdHash.data(), rpIdHash.size());
                std::memcpy(verificationData.data() + 1 + rpIdHash.size(), clientDataHash.data(), clientDataHash.size());
                std::memcpy(verificationData.data() + 1 + rpIdHash.size() + clientDataHash.size(), credentialID.data(), credentialID.size());
                std::memcpy(verificationData.data() + 1 + rpIdHash.size() + clientDataHash.size() + credentialID.size(), pubKeyData.data(), pubKeyData.size());

                // Step 6. Verify the sig using verificationData and certificate public key per SEC1[https://www.w3.org/TR/webauthn/#biblio-sec1].
                auto coseAlg = WebAuthNCOSE::COSEAlgorithmIdentifierType::AlgES256;
                auto sigAlg = WebAuthNCOSE::SigAlgFromCOSEAlg(coseAlg);
                auto signatureCheckResult = Util::Crypto::CheckSignature(attCertBytes, 
                                                                        WebAuthNCOSE::SignatureAlgorithmTypeToString(sigAlg), 
                                                                        verificationData, 
                                                                        signature);

                if (!signatureCheckResult || !signatureCheckResult.value()) {
                    return unexpected(ErrInvalidAttestation().WithDetails(signatureCheckResult ? "Signature validation error" : fmt::format("Signature validation error: {}", std::string(signatureCheckResult.error()))));
                }

                // Step 7. If successful, return attestation type Basic with the attestation trust path set to x5c.
                return std::make_tuple(json(Metadata::AuthenticatorAttestationType::BasicFull).get<std::string>(), std::optional<json>{x5c});
            }

            return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"));
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterU2FAttestation() noexcept {

        RegisterAttestationFormat(U2F_ATTESTATION_KEY, _VerifyU2FFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_U2F_IPP
