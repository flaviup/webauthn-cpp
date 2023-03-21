//
//  AttestationPlayIntegrity.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_PLAY_INTEGRITY_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_PLAY_INTEGRITY_IPP

#include <fmt/format.h>
#include <jwt.h>
#include "Attestation.ipp"
#include "Base64.ipp"
#include "../Metadata/Metadata.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/Time.ipp"
#include "../Util/StringCompare.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;
    
    inline const std::string PLAYINTEGRITY_ATTESTATION_KEY = "android-playintegrity";

#pragma GCC visibility push(hidden)

    namespace {

        enum class DeviceRecognitionVerdictType {

            MeetsBasicIntegrity,
            MeetsDeviceIntegrity,
            MeetsStrongIntegrity,
            MeetsVirtualIntegrity
        };

        // map DeviceRecognitionVerdictType values to JSON as strings
        NLOHMANN_JSON_SERIALIZE_ENUM(DeviceRecognitionVerdictType, {
            { DeviceRecognitionVerdictType::MeetsBasicIntegrity,                     nullptr },
            { DeviceRecognitionVerdictType::MeetsBasicIntegrity,                          "" },
            { DeviceRecognitionVerdictType::MeetsBasicIntegrity,     "MEETS_BASIC_INTEGRITY" },
            { DeviceRecognitionVerdictType::MeetsDeviceIntegrity,   "MEETS_DEVICE_INTEGRITY" },
            { DeviceRecognitionVerdictType::MeetsStrongIntegrity,   "MEETS_STRONG_INTEGRITY" },
            { DeviceRecognitionVerdictType::MeetsVirtualIntegrity, "MEETS_VIRTUAL_INTEGRITY" }
        })

        enum class AppRecognitionVerdictType {

            PlayRecognized,
            UnrecognizedVersion,
            Unevaluated
        };

        // map AppRecognitionVerdictType values to JSON as strings
        NLOHMANN_JSON_SERIALIZE_ENUM(AppRecognitionVerdictType, {
            { AppRecognitionVerdictType::UnrecognizedVersion,                nullptr },
            { AppRecognitionVerdictType::UnrecognizedVersion,                     "" },
            { AppRecognitionVerdictType::Unevaluated,                  "UNEVALUATED" },
            { AppRecognitionVerdictType::PlayRecognized,           "PLAY_RECOGNIZED" },
            { AppRecognitionVerdictType::UnrecognizedVersion, "UNRECOGNIZED_VERSION" }
        })

        enum class AppLicensingVerdictType {

            Licensed,
            Unlicensed,
            Unevaluated
        };

        // map AppLicensingVerdictType values to JSON as strings
        NLOHMANN_JSON_SERIALIZE_ENUM(AppLicensingVerdictType, {
            { AppLicensingVerdictType::Unevaluated,                        nullptr },
            { AppLicensingVerdictType::Unevaluated,                             "" },
            { AppLicensingVerdictType::Unevaluated,                  "UNEVALUATED" },
            { AppLicensingVerdictType::Licensed,                        "LICENSED" },
            { AppLicensingVerdictType::Unlicensed,                    "UNLICENSED" }
        })

        struct RequestDetailsType {

            // Application package name this attestation was requested for.
            // Note that this field might be spoofed in the middle of the
            // request.
            std::string RequestPackageName;
            // base64-encoded URL-safe no-wrap nonce provided by the developer.
            URLEncodedBase64Type Nonce;
            // The timestamp in milliseconds when the request was made
            // (computed on the server).
            int64_t TimestampMillis;
        };

        static inline void to_json(json& j, const RequestDetailsType& requestDetails) {

            j = json{
                { "requestPackageName", requestDetails.RequestPackageName },
                { "nonce",                           requestDetails.Nonce },
                { "timestampMillis",       requestDetails.TimestampMillis }
            };
        }

        static inline void from_json(const json& j, RequestDetailsType& requestDetails) {

            j.at("requestPackageName").get_to(requestDetails.RequestPackageName);
            j.at("nonce").get_to(requestDetails.Nonce);
            j.at("timestampMillis").get_to(requestDetails.TimestampMillis);
        }

        struct AppIntegrityType {

            AppRecognitionVerdictType AppRecognitionVerdict;
            // The package name of the app.
            // This field is populated iff AppRecognitionVerdict != Unevaluated.
            std::string PackageName;
            // The sha256 digest of app certificates.
            // This field is populated iff AppRecognitionVerdict != Unevaluated.
            std::vector<json> CertificateSha256Digest;
            // The version of the app.
            // This field is populated iff AppRecognitionVerdict != Unevaluated.
            int64_t VersionCode;
        };

        static inline void to_json(json& j, const AppIntegrityType& appIntegrity) {

            j = json{
                { "appRecognitionVerdict",     appIntegrity.AppRecognitionVerdict },
                { "packageName",                         appIntegrity.PackageName },
                { "certificateSha256Digest", appIntegrity.CertificateSha256Digest },
                { "versionCode",                         appIntegrity.VersionCode }
            };
        }

        static inline void from_json(const json& j, AppIntegrityType& appIntegrity) {

            j.at("appRecognitionVerdict").get_to(appIntegrity.AppRecognitionVerdict);
            j.at("packageName").get_to(appIntegrity.PackageName);
            j.at("certificateSha256Digest").get_to(appIntegrity.CertificateSha256Digest);
            j.at("versionCode").get_to(appIntegrity.VersionCode);
        }

        struct DeviceIntegrityType {
            
            std::vector<DeviceRecognitionVerdictType> DeviceRecognitionVerdict;
        };

        static inline void to_json(json& j, const DeviceIntegrityType& deviceIntegrity) {

            j = json{
                { "deviceRecognitionVerdict", deviceIntegrity.DeviceRecognitionVerdict }
            };
        }

        static inline void from_json(const json& j, DeviceIntegrityType& deviceIntegrity) {

            j.at("deviceRecognitionVerdict").get_to(deviceIntegrity.DeviceRecognitionVerdict);
        }

        struct AccountDetailsType {

            AppLicensingVerdictType AppLicensingVerdict;
        };

        static inline void to_json(json& j, const AccountDetailsType& accountDetails) {

            j = json{
                { "appLicensingVerdict", accountDetails.AppLicensingVerdict }
            };
        }

        static inline void from_json(const json& j, AccountDetailsType& accountDetails) {

            j.at("appLicensingVerdict").get_to(accountDetails.AppLicensingVerdict);
        }

        struct PlayIntegrityResponseType {

            PlayIntegrityResponseType() noexcept = default;

            PlayIntegrityResponseType(const json& j) :
                RequestDetails(j["requestDetails"].get<RequestDetailsType>()),
                AppIntegrity(j["appIntegrity"].get<AppIntegrityType>()),
                DeviceIntegrity(j["deviceIntegrity"].get<DeviceIntegrityType>()),
                AccountDetails(j["accountDetails"].get<AccountDetailsType>()),
                ApkDigestSha256(j["apkDigestSha256"].get<std::string>()) {
            }

            PlayIntegrityResponseType(const PlayIntegrityResponseType& playIntegrityResponse) noexcept = default;
            PlayIntegrityResponseType(PlayIntegrityResponseType&& playIntegrityResponse) noexcept = default;
            ~PlayIntegrityResponseType() noexcept = default;

            PlayIntegrityResponseType& operator =(const PlayIntegrityResponseType& other) noexcept = default;
            PlayIntegrityResponseType& operator =(PlayIntegrityResponseType&& other) noexcept = default;

            RequestDetailsType RequestDetails;
            AppIntegrityType AppIntegrity;
            DeviceIntegrityType DeviceIntegrity;
            AccountDetailsType AccountDetails;

            std::string ApkDigestSha256;
        };

        static inline void to_json(json& j, const PlayIntegrityResponseType& playIntegrityResponse) {

            j = json{
                { "requestDetails",   playIntegrityResponse.RequestDetails },
                { "appIntegrity",       playIntegrityResponse.AppIntegrity },
                { "deviceIntegrity", playIntegrityResponse.DeviceIntegrity },
                { "accountDetails",   playIntegrityResponse.AccountDetails },
                { "apkDigestSha256", playIntegrityResponse.ApkDigestSha256 }
            };
        }

        static inline void from_json(const json& j, PlayIntegrityResponseType& playIntegrityResponse) {

            j.at("requestDetails").get_to(playIntegrityResponse.RequestDetails);
            j.at("appIntegrity").get_to(playIntegrityResponse.AppIntegrity);
            j.at("deviceIntegrity").get_to(playIntegrityResponse.DeviceIntegrity);
            j.at("accountDetails").get_to(playIntegrityResponse.AccountDetails);
            j.at("apkDigestSha256").get_to(playIntegrityResponse.ApkDigestSha256);
        }

        static int _PlayIntegrityJwtKeyProvider(const jwt_t* jwt, jwt_key_t* jwtKey) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<URLEncodedBase64Type>();
                        auto decoded = URLEncodedBase64_DecodeAsBinary(cert);

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

        static inline std::vector<uint8_t> _PlayIntegrityGetFirstCertData(const jwt_t* jwt) {

            auto x5c = jwt_get_headers_json(const_cast<jwt_t*>(jwt), "x5c");

            if (x5c != nullptr) {

                try {
                    auto j = json::parse(x5c);

                    if (!j.empty() && j.is_array()) {

                        auto cert = j[0].get<URLEncodedBase64Type>();
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

        // §8.5. Android Play Integrity Attestation Statement Format 
        static inline expected<std::tuple<std::string, std::optional<json>>>
        _VerifyPlayIntegrityFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // The syntax of an Android Attestation statement is defined as follows:
            //     $$attStmtType //= (
            //                           fmt: "android-playintegrity",
            //                           attStmt: playIntegrityStmtFormat
            //                       )

            //     playIntegrityStmtFormat = {
            //                               ver: text,
            //                               response: bytes
            //                           }

            // §8.5.1 Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
            // the contained fields.

            // We have done this
            // §8.5.2 Verify that response is a valid PlayIntegrity response of version ver.
            if (att.AttStatement) {

                auto atts = att.AttStatement.value();

                if (atts.find("ver") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to find the version of Play Integrity"));
                }
                auto version = atts["ver"].get<std::string>();

                if (version.empty()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Not a proper version for Play Integrity"));
                }

                if (atts.find("response") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to find the Play Integrity response"));
                }
                auto response = atts["response"].get_binary();
                jwt_t* jwt = nullptr;
                auto responseStr = std::string(reinterpret_cast<const char*>(response.data()), response.size());
                auto ret = jwt_decode_2(&jwt, responseStr.data(), _PlayIntegrityJwtKeyProvider);

                if (ret != 0 || jwt == nullptr) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // marshall the JWT payload into the Play Integrity response json
                PlayIntegrityResponseType playIntegrityResponse{};
                auto grants = jwt_get_grants_json(jwt, nullptr);

                if (grants != nullptr) {

                    try {

                        auto j = json::parse(grants);
                        j.get_to(playIntegrityResponse);
                    } catch (const std::exception& ex) {

                        jwt_free_str(grants);
                        jwt_free(jwt);

                        return unexpected(ErrAttestationFormat().WithDetails(fmt::format("Error parsing the Play Integrity response", ex.what())));
                    }
                    jwt_free_str(grants);
                }

                // §8.5.3 Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation
                // of authenticatorData and clientDataHash.
                std::vector<uint8_t> nonce(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(nonce.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(nonce.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());
                auto nonceBuffer = Util::Crypto::SHA256(nonce);
                auto nonceBytesResult = URLEncodedBase64_DecodeAsBinary(playIntegrityResponse.RequestDetails.Nonce, false);

                if (!nonceBytesResult || !Util::StringCompare::ConstantTimeEqual(nonceBuffer, nonceBytesResult.value())) {

                    jwt_free(jwt);
                    return unexpected(ErrInvalidAttestation().WithDetails("Invalid nonce for in Play Integrity response"));
                }

                // §8.5.4 Let attestationCert be the attestation certificate (https://www.w3.org/TR/webauthn/#attestation-certificate)
                auto certData = _PlayIntegrityGetFirstCertData(jwt);
                jwt_free(jwt);

                if (certData.empty()) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
                auto certVerifHostnameResult = Util::Crypto::VerifyCertificateHostname(certData, "attest.android.com");

                if (!certVerifHostnameResult || !certVerifHostnameResult.value()) {
                    return unexpected(ErrInvalidAttestation().WithDetails("Error finding cert issued to correct hostname"));
                }

                // §8.5.6 Verify that the DeviceRecognitionVerdict attribute in the payload of response meets the necessary integrity.
                const auto& v = playIntegrityResponse.DeviceIntegrity.DeviceRecognitionVerdict;

                if (v.empty() || 
                    std::find(v.cbegin(), v.cend(), DeviceRecognitionVerdictType::MeetsBasicIntegrity) == v.cend() ||
                    std::find(v.cbegin(), v.cend(), DeviceRecognitionVerdictType::MeetsDeviceIntegrity) == v.cend()) {

                    return unexpected(ErrInvalidAttestation().WithDetails("DeviceRecognitionVerdict attribute of the JWT payload does not have the necessary integrity labels"));
                }

                // Verify sanity of timestamp in the payload
                auto now = Util::Time::Timestamp();
                auto oneMinuteAgo = now - 60'000;
                
                if (playIntegrityResponse.RequestDetails.TimestampMillis > now) {
                    // zero tolerance for post-dated timestamps
                    return unexpected(ErrInvalidAttestation().WithDetails("Play Integrity response with timestamp after current time"));
                } else if (playIntegrityResponse.RequestDetails.TimestampMillis < oneMinuteAgo) {

                    // allow old timestamp for testing purposes
                    // TODO: Make this user configurable
                    if (Metadata::Conformance) {
                        return unexpected(ErrInvalidAttestation().WithDetails("Play Integrity response with timestamp before one minute ago"));
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

    inline void RegisterPlayIntegrityAttestation() noexcept {

        RegisterAttestationFormat(PLAYINTEGRITY_ATTESTATION_KEY, _VerifyPlayIntegrityFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_PLAY_INTEGRITY_IPP
