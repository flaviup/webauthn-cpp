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
#include "Base64.ipp"
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
                Nonce(j["nonce"].get<std::string>()),
                TimestampMs(j["timestampMs"].get<int64_t>()),
                ApkPackageName(j["apkPackageName"].get<std::string>()),
                ApkDigestSha256(j["apkDigestSha256"].get<std::string>()),
                CtsProfileMatch(j["ctsProfileMatch"].get<bool>()),
                ApkCertificateDigestSha256(j["apkCertificateDigestSha256"].get<std::vector<json::object_t>>()),
                BasicIntegrity(j["basicIntegrity"].get<bool>()) {
            }

            SafetyNetResponseType(const SafetyNetResponseType& safetyNetResponse) noexcept = default;
            SafetyNetResponseType(SafetyNetResponseType&& safetyNetResponse) noexcept = default;
            ~SafetyNetResponseType() noexcept = default;

            SafetyNetResponseType& operator =(const SafetyNetResponseType& other) noexcept = default;
            SafetyNetResponseType& operator =(SafetyNetResponseType&& other) noexcept = default;

            std::string Nonce;
            int64_t TimestampMs;
            std::string ApkPackageName;
            std::string ApkDigestSha256;
            bool CtsProfileMatch;
            std::vector<json::object_t> ApkCertificateDigestSha256;
            bool BasicIntegrity;
        };

        inline void to_json(json& j, const SafetyNetResponseType& safetyNetResponse) {

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

        inline void from_json(const json& j, SafetyNetResponseType& safetyNetResponse) {

            j.at("nonce").get_to(safetyNetResponse.Nonce);
            j.at("timestampMs").get_to(safetyNetResponse.TimestampMs);
            j.at("apkPackageName").get_to(safetyNetResponse.ApkPackageName);
            j.at("apkDigestSha256").get_to(safetyNetResponse.ApkDigestSha256);
            j.at("ctsProfileMatch").get_to(safetyNetResponse.CtsProfileMatch);
            j.at("apkCertificateDigestSha256").get_to(safetyNetResponse.ApkCertificateDigestSha256);
            j.at("basicIntegrity").get_to(safetyNetResponse.BasicIntegrity);
        }

        int JwtKeyProvider(const jwt_t* jwt, jwt_key_t* jwtKey) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<std::string>();
                        auto decoded = URLEncodedBase64_DecodeAsBinary(cert);

                        if (decoded) {

                            auto certPublicKeyParsing = Util::Crypto::ParseCertificatePublicKey(decoded.value());

                            if (certPublicKeyParsing) {

                                auto pubKey = certPublicKeyParsing.value();
                                jwtKey->jwt_key_len = static_cast<int>(pubKey.size());
                                auto pubKeyBuffer = malloc(jwtKey->jwt_key_len);
                                std::memcpy(pubKeyBuffer, pubKey.data(), jwtKey->jwt_key_len);
                                jwtKey->jwt_key = reinterpret_cast<unsigned char*>(pubKeyBuffer);
                                jwt_free_str(x5c);

                                return 0;
                            }
                        }
                    }
                } catch (const std::exception&) {
                }
                jwt_free_str(x5c);
            }

            return -1;
        }

        std::vector<uint8_t> GetFirstCertData(const jwt_t* jwt) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<std::string>();
                        auto decoded = URLEncodedBase64_DecodeAsBinary(cert);

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
        //	some statements about the health of the platform and the identity of the calling application. This attestation does not
        //
        // provide information regarding provenance of the authenticator and its associated data. Therefore platform-provided
        // authenticators SHOULD make use of the Android Key Attestation when available, even if the SafetyNet API is also present.
        inline expected<std::tuple<std::string, std::optional<json::object_t>>>
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
                auto response = atts["response"].get<std::string>();
                jwt_t* jwt = nullptr;
                auto ret = jwt_decode_2(&jwt, response.data(), JwtKeyProvider);

                if (ret != 0 || jwt == nullptr) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }
                
                // marshall the JWT payload into the SafetyNet response json
                SafetyNetResponseType safetyNetResponse{};
                auto grants = jwt_get_grants_json(jwt, "Claims");

                if (grants != nullptr) {

                    try {

                        auto j = json::parse(grants);
                        j.get_to(safetyNetResponse);
                    } catch (const std::exception& ex) {

                        jwt_free_str(grants);
                        jwt_free(jwt);

                        return unexpected(ErrAttestationFormat().WithDetails(fmt::format("Error parsing the SafetyNet response", ex.what())));
                    }
                }
                jwt_free_str(grants);

                // §8.5.3 Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation
                // of authenticatorData and clientDataHash.
                std::vector<uint8_t> nonce(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(nonce.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(nonce.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());
                auto nonceBuffer = Util::Crypto::SHA256(nonce);
                auto nonceBytesResult = URLEncodedBase64_DecodeAsBinary(safetyNetResponse.Nonce);

                if (!nonceBytesResult || !Util::StringCompare::ConstantTimeEqual(nonceBuffer, nonceBytesResult.value())) {

                    jwt_free(jwt);
                    return unexpected(ErrInvalidAttestation().WithDetails("Invalid nonce for in SafetyNet response"));
                }

                // §8.5.4 Let attestationCert be the attestation certificate (https://www.w3.org/TR/webauthn/#attestation-certificate)
                auto certData = GetFirstCertData(jwt);
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

                // §8.5.7 If successful, return implementation-specific values representing attestation type Basic and attestation
                // trust path attestationCert.
                return std::tuple{json(Metadata::AuthenticatorAttestationType::BasicFull).get<std::string>(), std::nullopt};
            } else {
                return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"));
            }

/*
            token, err := jwt.Parse(string(response), func(token *jwt.Token) (interface{}, error) {
                chain := token.Header["x5c"].([]interface{})

                o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

                n, err := base64.StdEncoding.Decode(o, []byte(chain[0].(string)))
                if err != nil {
                    return nil, err
                }

                cert, err := x509.ParseCertificate(o[:n])
                return cert.PublicKey, err
            })

            if err != nil {
                return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error finding cert issued to correct hostname: %+v", err))
            }

            // marshall the JWT payload into the safetynet response json
            var safetyNetResponse SafetyNetResponse

            if err = mapstructure.Decode(token.Claims, &safetyNetResponse); err != nil {
                return "", nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing the SafetyNet response: %+v", err))
            }

            // §8.5.3 Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation
            // of authenticatorData and clientDataHash.
            nonceBuffer := sha256.Sum256(append(att.RawAuthData, clientDataHash...))

            nonceBytes, err := base64.StdEncoding.DecodeString(safetyNetResponse.Nonce)
            if !bytes.Equal(nonceBuffer[:], nonceBytes) || err != nil {
                return "", nil, ErrInvalidAttestation.WithDetails("Invalid nonce for in SafetyNet response")
            }

            // §8.5.4 Let attestationCert be the attestation certificate (https://www.w3.org/TR/webauthn/#attestation-certificate)
            certChain := token.Header["x5c"].([]interface{})
            l := make([]byte, base64.StdEncoding.DecodedLen(len(certChain[0].(string))))

            n, err := base64.StdEncoding.Decode(l, []byte(certChain[0].(string)))
            if err != nil {
                return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error finding cert issued to correct hostname: %+v", err))
            }

            attestationCert, err := x509.ParseCertificate(l[:n])
            if err != nil {
                return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error finding cert issued to correct hostname: %+v", err))
            }

            // §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
            err = attestationCert.VerifyHostname("attest.android.com")
            if err != nil {
                return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error finding cert issued to correct hostname: %+v", err))
            }

            // §8.5.6 Verify that the ctsProfileMatch attribute in the payload of response is true.
            if !safetyNetResponse.CtsProfileMatch {
                return "", nil, ErrInvalidAttestation.WithDetails("ctsProfileMatch attribute of the JWT payload is false")
            }

            // Verify sanity of timestamp in the payload
            now := time.Now()
            oneMinuteAgo := now.Add(-time.Minute)

            if t := time.Unix(safetyNetResponse.TimestampMs/1000, 0); t.After(now) {
                // zero tolerance for post-dated timestamps
                return "", nil, ErrInvalidAttestation.WithDetails("SafetyNet response with timestamp after current time")
            } else if t.Before(oneMinuteAgo) {
                // allow old timestamp for testing purposes
                // TODO: Make this user configurable
                msg := "SafetyNet response with timestamp before one minute ago"
                if metadata.Conformance {
                    return "", nil, ErrInvalidAttestation.WithDetails(msg)
                }
            }*/
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterSafetyNetAttestation() noexcept {

        RegisterAttestationFormat(SAFETYNET_ATTESTATION_KEY, _VerifySafetyNetFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_SAFETY_NET_IPP
