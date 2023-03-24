//
//  AttestationSafetyNet.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/11/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_SAFETY_NET_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_SAFETY_NET_IPP

#include <fmt/format.h>
#include <jwt.h>
#include "Attestation.ipp"
#include "../Metadata/Metadata.ipp"
#include "../Util/Base64.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/Time.ipp"
#include "../Util/StringCompare.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;
    
    inline const std::string SAFETYNET_ATTESTATION_KEY = "android-safetynet";

#pragma GCC visibility push(hidden)

    namespace {

        struct SafetyNetResponseType {

            SafetyNetResponseType() noexcept = default;

            SafetyNetResponseType(const json& j) :
                Nonce(j["nonce"].get<Util::Base64EncodedType>()),
                TimestampMs(j["timestampMs"].get<int64_t>()),
                ApkPackageName(j["apkPackageName"].get<std::string>()),
                ApkDigestSha256(j["apkDigestSha256"].get<std::string>()),
                CtsProfileMatch(j["ctsProfileMatch"].get<bool>()),
                ApkCertificateDigestSha256(j["apkCertificateDigestSha256"].get<std::vector<json>>()),
                BasicIntegrity(j["basicIntegrity"].get<bool>()) {
            }

            SafetyNetResponseType(const SafetyNetResponseType& safetyNetResponse) noexcept = default;
            SafetyNetResponseType(SafetyNetResponseType&& safetyNetResponse) noexcept = default;
            ~SafetyNetResponseType() noexcept = default;

            SafetyNetResponseType& operator =(const SafetyNetResponseType& other) noexcept = default;
            SafetyNetResponseType& operator =(SafetyNetResponseType&& other) noexcept = default;

            Util::Base64EncodedType Nonce;
            int64_t TimestampMs;
            std::string ApkPackageName;
            std::string ApkDigestSha256;
            bool CtsProfileMatch;
            std::vector<json> ApkCertificateDigestSha256;
            bool BasicIntegrity;
        };

        static inline void to_json(json& j, const SafetyNetResponseType& safetyNetResponse) {

            j = json{
                { "nonce",                                           safetyNetResponse.Nonce },
                { "timestampMs",                               safetyNetResponse.TimestampMs },
                { "apkPackageName",                         safetyNetResponse.ApkPackageName },
                { "apkDigestSha256",                       safetyNetResponse.ApkDigestSha256 },
                { "ctsProfileMatch",                       safetyNetResponse.CtsProfileMatch },
                { "apkCertificateDigestSha256", safetyNetResponse.ApkCertificateDigestSha256 },
                { "basicIntegrity",                         safetyNetResponse.BasicIntegrity }
            };
        }

        static inline void from_json(const json& j, SafetyNetResponseType& safetyNetResponse) {

            j.at("nonce").get_to(safetyNetResponse.Nonce);
            j.at("timestampMs").get_to(safetyNetResponse.TimestampMs);
            j.at("apkPackageName").get_to(safetyNetResponse.ApkPackageName);
            j.at("apkDigestSha256").get_to(safetyNetResponse.ApkDigestSha256);
            j.at("ctsProfileMatch").get_to(safetyNetResponse.CtsProfileMatch);
            j.at("apkCertificateDigestSha256").get_to(safetyNetResponse.ApkCertificateDigestSha256);
            j.at("basicIntegrity").get_to(safetyNetResponse.BasicIntegrity);
        }

        static int _SafetyNetJwtKeyProvider(const jwt_t* jwt, jwt_key_t* jwtKey) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<Util::Base64EncodedType>();
                        auto decoded = Util::Base64_DecodeAsBinary(cert);

                        if (decoded) {

                            auto certPublicKeyParsing = Util::Crypto::ParseCertificatePublicKey(decoded.value());

                            if (certPublicKeyParsing) {

                                auto pubKey = certPublicKeyParsing.value();
                                jwtKey->jwt_key_len = 0;
                                jwtKey->jwt_key = nullptr;
                                jwt_free_str(x5c);
                                auto size = pubKey.size();

                                if (size > 1) {
                                    return jwt_set_alg(const_cast<jwt_t*>(jwt), jwt_get_alg(jwt),
                                                       reinterpret_cast<const unsigned char*>(pubKey.data()),
                                                       static_cast<int>(pubKey[size - 1] == '\n' ? size - 1 : size));
                                } else {
                                    return EINVAL;
                                }
                            }
                        }
                    }
                } catch (const std::exception&) {
                }
                jwt_free_str(x5c);
            }

            return EINVAL;
        }

        static inline std::vector<uint8_t> _SafetyNetGetFirstCertData(const jwt_t* jwt) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<Util::Base64EncodedType>();
                        auto decoded = Util::Base64_DecodeAsBinary(cert);

                        if (decoded) {

                            jwt_free_str(x5c);
                            return decoded.value();
                        }
                    }
                } catch (const std::exception&) {
                }
                jwt_free_str(x5c);
            }

            return std::vector<uint8_t>{};
        }

        // Thanks to @koesie10 and @herrjemand for outlining how to support this type really well

        // §8.5. Android SafetyNet Attestation Statement Format https://www.w3.org/TR/webauthn/#android-safetynet-attestation
        // When the authenticator in question is a platform-provided Authenticator on certain Android platforms, the attestation
        // statement is based on the SafetyNet API. In this case the authenticator data is completely controlled by the caller of
        // the SafetyNet API (typically an application running on the Android platform) and the attestation statement only provides
        //
        // some statements about the health of the platform and the identity of the calling application. This attestation does not
        //
        // provide information regarding provenance of the authenticator and its associated data. Therefore platform-provided
        // authenticators SHOULD make use of the Android Key Attestation when available, even if the SafetyNet API is also present.
        static inline expected<std::tuple<std::string, std::optional<json>>>
        _VerifySafetyNetFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // The syntax of an Android Attestation statement is defined as follows:
            //     $$attStmtType //= (
            //                           fmt: "android-safetynet",
            //                           attStmt: safetynetStmtFormat
            //                       )

            //     safetynetStmtFormat = {
            //                               ver: text,
            //                               response: bytes
            //                           }

            // §8.5.1 Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
            // the contained fields.

            // We have done this
            // §8.5.2 Verify that response is a valid SafetyNet response of version ver.
            if (att.AttStatement) {

                auto atts = att.AttStatement.value();

                if (atts.find("ver") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to find the version of SafetyNet"));
                }
                auto version = atts["ver"].get<std::string>();

                if (version.empty()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Not a proper version for SafetyNet"));
                }

                // TODO: provide user the ability to designate their supported versions

                if (atts.find("response") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to find the SafetyNet response"));
                }
                auto response = atts["response"].get_binary();
                jwt_t* jwt = nullptr;
                auto responseStr = std::string(reinterpret_cast<const char*>(response.data()), response.size());
                auto ret = jwt_decode_2(&jwt, responseStr.data(), _SafetyNetJwtKeyProvider);

                if (ret != 0 || jwt == nullptr) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // marshall the JWT payload into the SafetyNet response json
                SafetyNetResponseType safetyNetResponse{};
                auto grants = jwt_get_grants_json(jwt, nullptr);

                if (grants != nullptr) {

                    try {

                        auto j = json::parse(grants);
                        j.get_to(safetyNetResponse);
                    } catch (const std::exception& ex) {

                        jwt_free_str(grants);
                        jwt_free(jwt);

                        return unexpected(ErrAttestationFormat().WithDetails(fmt::format("Error parsing the SafetyNet response", ex.what())));
                    }
                    jwt_free_str(grants);
                }

                // §8.5.3 Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation
                // of authenticatorData and clientDataHash.
                std::vector<uint8_t> nonce(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(nonce.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(nonce.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());
                auto nonceBuffer = Util::Crypto::SHA256(nonce);
                auto nonceBytesResult = Util::Base64_DecodeAsBinary(safetyNetResponse.Nonce, false);

                if (!nonceBytesResult || !Util::StringCompare::ConstantTimeEqual(nonceBuffer, nonceBytesResult.value())) {

                    jwt_free(jwt);
                    return unexpected(ErrInvalidAttestation().WithDetails("Invalid nonce for in SafetyNet response"));
                }

                // §8.5.4 Let attestationCert be the attestation certificate (https://www.w3.org/TR/webauthn/#attestation-certificate)
                auto certData = _SafetyNetGetFirstCertData(jwt);
                jwt_free(jwt);

                if (certData.empty()) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
                auto certVerifHostnameResult = Util::Crypto::VerifyCertificateHostname(certData, "attest.android.com");

                if (!certVerifHostnameResult || !certVerifHostnameResult.value()) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // §8.5.6 Verify that the ctsProfileMatch attribute in the payload of response is true.
                if (!safetyNetResponse.CtsProfileMatch) {
                    return unexpected(ErrInvalidAttestation().WithDetails("ctsProfileMatch attribute of the JWT payload is false"));
                }

                // Verify sanity of timestamp in the payload
                auto now = Util::Time::Timestamp();
                auto oneMinuteAgo = now - 60'000;
                
                if (safetyNetResponse.TimestampMs > now) {
                    // zero tolerance for post-dated timestamps
                    return unexpected(ErrInvalidAttestation().WithDetails("SafetyNet response with timestamp after current time"));
                } else if (safetyNetResponse.TimestampMs < oneMinuteAgo) {

                    // allow old timestamp for testing purposes
                    // TODO: Make this user configurable
                    if (Metadata::Conformance) {
                        return unexpected(ErrInvalidAttestation().WithDetails("SafetyNet response with timestamp before one minute ago"));
                    }
                }

                // §8.5.7 If successful, return implementation-specific values representing attestation type Basic and attestation
                // trust path attestationCert.
                return std::tuple{json(Metadata::AuthenticatorAttestationType::BasicFull).get<std::string>(), std::nullopt};
            } else {
                return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"));
            }
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterSafetyNetAttestation() noexcept {

        RegisterAttestationFormat(SAFETYNET_ATTESTATION_KEY, _VerifySafetyNetFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_SAFETY_NET_IPP
