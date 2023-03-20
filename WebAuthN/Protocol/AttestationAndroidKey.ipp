//
//  AttestationAndroidKey.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/10/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_ANDROID_KEY_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_ANDROID_KEY_IPP

#include <set>
#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/StringCompare.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using namespace std::string_literals;
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

        enum class SecurityLevelType : int {

            Software,
            TrustedEnvironment,
            StrongBox
        };

        struct RootOfTrustType {

            std::vector<uint8_t> VerifiedBootKey;
            bool DeviceLocked;
            VerifiedBootStateType VerifiedBootState;
            std::vector<uint8_t> VerifiedBootHash;
        };

        /** Specifies the types of user authenticators that may be used to authorize this key. */
        enum class UserAuthType : int {

            None,
            Password,
            Fingerprint,
            Any
        };

        /** Provides package's name and version number. */
        struct AttestationPackageInfoType {

            std::string PackageName;
            int64_t Version;
        };

        /**
         * This data structure reflects the Android platform's belief as to which apps are allowed to use
         * the secret key material under attestation. The ID can comprise multiple packages if and only if
         * multiple packages share the same UID.
         */
        struct AttestationApplicationIDType {

            std::vector<AttestationPackageInfoType> PackageInfos;
            std::vector<std::vector<uint8_t>> SignatureDigests;
        };

        /**
         * This data structure contains the key pair's properties themselves, as defined in the Keymaster
         * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
         * set of expected values to verify that a key pair is still valid for use in your app.
         */
        struct AuthorizationListType {

            static inline constexpr auto PURPOSE_TAG                        =   1;
            static inline constexpr auto ALGORITHM_TAG                      =   2;
            static inline constexpr auto KEY_SIZE_TAG                       =   3;
            static inline constexpr auto DIGEST_TAG                         =   5;
            static inline constexpr auto PADDING_TAG                        =   6;
            static inline constexpr auto EC_CURVE_TAG                       =  10;
            static inline constexpr auto RSA_PUBLIC_EXPONENT_TAG            = 200;
            static inline constexpr auto ROLLBACK_RESISTANCE_TAG            = 303;
            static inline constexpr auto ACTIVE_DATE_TIME_TAG               = 400;
            static inline constexpr auto ORIGINATION_DATE_TIME_TAG          = 401;
            static inline constexpr auto USAGE_EXPIRE_DATE_TIME_TAG         = 402;
            static inline constexpr auto NO_AUTH_REQUIRED_TAG               = 503;
            static inline constexpr auto USER_AUTH_TYPE_TAG                 = 504;
            static inline constexpr auto AUTH_TIMEOUT_TAG                   = 505;
            static inline constexpr auto ALLOW_WHILE_ON_BODY_TAG            = 506;
            static inline constexpr auto TRUSTED_USER_PRESENCE_REQUIRED_TAG = 507;
            static inline constexpr auto TRUSTED_CONFIRMATION_REQUIRED_TAG  = 508;
            static inline constexpr auto UNLOCKED_DEVICE_REQUIRED_TAG       = 509;
            static inline constexpr auto ALL_APPLICATIONS_TAG               = 600;
            static inline constexpr auto APPLICATION_ID_TAG                 = 601;
            static inline constexpr auto CREATION_DATE_TIME_TAG             = 701;
            static inline constexpr auto ORIGIN_TAG                         = 702;
            static inline constexpr auto ROLLBACK_RESISTANT_TAG             = 703;
            static inline constexpr auto ROOT_OF_TRUST_TAG                  = 704;
            static inline constexpr auto OS_VERSION_TAG                     = 705;
            static inline constexpr auto OS_PATCH_LEVEL_TAG                 = 706;
            static inline constexpr auto ATTESTATION_APPLICATION_ID_TAG     = 709;
            static inline constexpr auto ATTESTATION_ID_BRAND_TAG           = 710;
            static inline constexpr auto ATTESTATION_ID_DEVICE_TAG          = 711;
            static inline constexpr auto ATTESTATION_ID_PRODUCT_TAG         = 712;
            static inline constexpr auto ATTESTATION_ID_SERIAL_TAG          = 713;
            static inline constexpr auto ATTESTATION_ID_IMEI_TAG            = 714;
            static inline constexpr auto ATTESTATION_ID_MEID_TAG            = 715;
            static inline constexpr auto ATTESTATION_ID_MANUFACTURER_TAG    = 716;
            static inline constexpr auto ATTESTATION_ID_MODEL_TAG           = 717;
            static inline constexpr auto VENDOR_PATCH_LEVEL_TAG             = 718;
            static inline constexpr auto BOOT_PATCH_LEVEL_TAG               = 719;
            static inline constexpr auto DEVICE_UNIQUE_ATTESTATION_TAG      = 720;
            static inline constexpr auto IDENTITY_CREDENTIAL_KEY_TAG        = 721;

            std::optional<int32_t>                      Purpose;                     // `asn1:"tag:1,explicit,set,optional"`
            std::optional<int32_t>                      Algorithm;                   // `asn1:"tag:2,explicit,optional"`
            std::optional<int32_t>                      KeySize;                     // `asn1:"tag:3,explicit,optional"`
            std::optional<std::set<int32_t>>            Digest;                      // `asn1:"tag:5,explicit,set,optional"`
            std::optional<std::set<int32_t>>            Padding;                     // `asn1:"tag:6,explicit,set,optional"`
            std::optional<int32_t>                      EcCurve;                     // `asn1:"tag:10,explicit,optional"`
            std::optional<int64_t>                      RsaPublicExponent;           // `asn1:"tag:200,explicit,optional"`
            bool                                        RollbackResistance;          // `asn1:"tag:303,explicit"`
            std::optional<int32_t>                      ActiveDateTime;              // `asn1:"tag:400,explicit,optional"`
            std::optional<int32_t>                      OriginationExpireDateTime;   // `asn1:"tag:401,explicit,optional"`
            std::optional<int32_t>                      UsageExpireDateTime;         // `asn1:"tag:402,explicit,optional"`
            bool                                        NoAuthRequired;              // `asn1:"tag:503,explicit"`
            std::optional<UserAuthType>                 UserAuthType;                // `asn1:"tag:504,explicit,optional"`
            std::optional<int32_t>                      AuthTimeout;                 // `asn1:"tag:505,explicit,optional"`
            bool                                        AllowWhileOnBody;            // `asn1:"tag:506,explicit"`
            bool                                        TrustedUserPresenceRequired; // `asn1:"tag:507,explicit"`
            bool                                        TrustedConfirmationRequired; // `asn1:"tag:508,explicit"`
            bool                                        UnlockedDeviceRequired;      // `asn1:"tag:509,explicit"`
            bool                                        AllApplications;             // `asn1:"tag:600,explicit"`
            std::optional<std::vector<uint8_t>>         ApplicationID;               // `asn1:"tag:601,explicit,optional"`
            std::optional<int32_t>                      CreationDateTime;            // `asn1:"tag:701,explicit,optional"`
            std::optional<KmKeyOriginType>              Origin;                      // `asn1:"tag:702,explicit,optional"`
            bool                                        RollbackResistant;           // `asn1:"tag:703,explicit"`
            std::optional<RootOfTrustType>              RootOfTrust;                 // `asn1:"tag:704,explicit,optional"`
            std::optional<int32_t>                      OsVersion;                   // `asn1:"tag:705,explicit,optional"`
            std::optional<int32_t>                      OsPatchLevel;                // `asn1:"tag:706,explicit,optional"`
            std::optional<AttestationApplicationIDType> AttestationApplicationID;    // `asn1:"tag:709,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDBrand;          // `asn1:"tag:710,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDDevice;         // `asn1:"tag:711,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDProduct;        // `asn1:"tag:712,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDSerial;         // `asn1:"tag:713,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDImei;           // `asn1:"tag:714,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDMeid;           // `asn1:"tag:715,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDManufacturer;   // `asn1:"tag:716,explicit,optional"`
            std::optional<std::vector<uint8_t>>         AttestationIDModel;          // `asn1:"tag:717,explicit,optional"`
            std::optional<int32_t>                      VendorPatchLevel;            // `asn1:"tag:718,explicit,optional"`
            std::optional<int32_t>                      BootPatchLevel;              // `asn1:"tag:719,explicit,optional"`
            bool                                        DeviceUniqueAttestation;     // `asn1:"tag:720,explicit"`
            bool                                        IdentityCredentialKey;       // `asn1:"tag:721,explicit"`
        };

        struct KeyDescriptionType {

            int32_t               AttestationVersion;
            SecurityLevelType     AttestationSecurityLevel;
            int32_t               KeymasterVersion;
            SecurityLevelType     KeymasterSecurityLevel;
            std::vector<uint8_t>  AttestationChallenge;
            std::vector<uint8_t>  UniqueID;
            AuthorizationListType SoftwareEnforced;
            AuthorizationListType TeeEnforced;
        };

        static inline expected<std::vector<uint8_t>>
        _Identity(const std::vector<uint8_t>& data) noexcept {
            return data;
        }

        static inline expected<bool>
        _ToBool(const std::vector<uint8_t>& data) noexcept {

            if (data.empty()) {
                return unexpected("Data vector is empty"s);
            }

            return data[0] != 0;
        }

        static inline expected<int32_t>
        _ToInt32(const std::vector<uint8_t>& data) noexcept {

            if (data.size() < 4) {
                return unexpected("Data vector size is less than 4 bytes"s);
            }

            return static_cast<int32_t>(MAKE_UINT32(data[0], data[1], data[2], data[3]));
        }

        static inline expected<int64_t>
        _ToInt64(const std::vector<uint8_t>& data) noexcept {

            if (data.size() < 8) {
                return unexpected("Data vector size is less than 8 bytes"s);
            }

            return static_cast<int64_t>(MAKE_UINT64(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]));
        }

        static inline expected<std::set<int32_t>>
        _ToInt32Set(const std::vector<uint8_t>& data) noexcept {

            if (data.size() % 4 != 0) {
                return unexpected("Data vector size is not a multiple of 4"s);
            }
            auto n = data.size() / 4;
            std::vector<int32_t> value(n);

            for (auto i = 0; i < n; ++i) {
                value[i] = static_cast<int32_t>(MAKE_UINT32(data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3]));
            }

            return std::set(value.data(), value.data() + n);
        }

        template<typename T>
        static inline expected<T>
        _ToIntEnum(const std::vector<uint8_t>& data) noexcept {

            if (data.size() < 4) {
                return unexpected("Data vector size is less than 4 bytes"s);
            }

            return static_cast<T>(static_cast<int>(MAKE_UINT32(data[0], data[1], data[2], data[3])));
        }

#define ASSIGN_ASN1(x, y) \
auto result = (y);\
\
if (!result) {\
    return unexpected("ASN1 map parsing error"s);\
}\
x = result.value()

#define ASSIGN_ASN1_FIELD(field, fieldTag, conversionFunction, defaultValue) \
if (asn1Map.find(fieldTag) == asn1Map.cend()) {\
    field = (defaultValue);\
} else {\
    ASSIGN_ASN1(field, conversionFunction(asn1Map[fieldTag]));\
}
        static inline expected<std::vector<AttestationPackageInfoType>>
        _ASN1UnmarshalAttestPackageInfos(const std::vector<uint8_t>& data) noexcept {

            if (data.empty()) {
                return unexpected("ASN1 parsing error of AttestationPackageInfoTypes in Android Key Attestation"s);
            }
            auto p = data.data();
            auto end = p + data.size();
            auto retSequence = Util::Crypto::ASN1GetSequence(p);

            if (!retSequence || p + retSequence.value() != end) {
                return unexpected("ASN1 parsing error of AttestationPackageInfoTypes in Android Key Attestation"s);
            }
            std::vector<AttestationPackageInfoType> attPackageInfos{};

            while (p < end) {

                AttestationPackageInfoType attPackageInfo{};
                auto retBytes = Util::Crypto::ASN1GetBytes(p);

                if (!retBytes) {
                    return unexpected("ASN1 parsing error of AttestationPackageInfoType in Android Key Attestation"s);
                }
                const auto& data2 = retBytes.value();
                auto p2 = data2.data();
                auto end2 = p2 + data2.size();
                retSequence = Util::Crypto::ASN1GetSequence(p2);

                if (!retSequence || p2 + retSequence.value() != end2) {
                    return unexpected("ASN1 parsing error of AttestationPackageInfoType in Android Key Attestation"s);
                }
                retBytes = Util::Crypto::ASN1GetBytes(p2);

                if (retBytes) {

                    auto v = retBytes.value();
                    attPackageInfo.PackageName = std::string(v.data(), v.data() + v.size());

                } else {
                    return unexpected("ASN1 parsing error of AttestationPackageInfoType::PackageName in Android Key Attestation"s);
                }
                auto retInt = p2 < end2 ? Util::Crypto::ASN1GetInt<int64_t>(p2) : unexpected(""s);

                if (retInt) {
                    attPackageInfo.Version = retInt.value();
                } else {
                    return unexpected("ASN1 parsing error of AttestationPackageInfoType::Version in Android Key Attestation"s);
                }

                attPackageInfos.push_back(attPackageInfo);
            }

            return attPackageInfos;
        }

        static inline expected<std::vector<std::vector<uint8_t>>>
        _ASN1UnmarshalAttestSignatureDigests(const std::vector<uint8_t>& data) noexcept {

            if (data.empty()) {
                return unexpected("ASN1 parsing error of SignatureDigests in Android Key Attestation"s);
            }
            auto p = data.data();
            auto end = p + data.size();

            auto retSequence = Util::Crypto::ASN1GetSequence(p);

            if (!retSequence || p + retSequence.value() != end) {
                return unexpected("ASN1 parsing error of SignatureDigests in Android Key Attestation"s);
            }
            std::vector<std::vector<uint8_t>> attSignatureDigests{};

            while (p < end) {

                auto retBytes = Util::Crypto::ASN1GetBytes(p);

                if (retBytes) {
                    attSignatureDigests.push_back(retBytes.value());
                } else {
                    return unexpected("ASN1 parsing error of SignatureDigests in Android Key Attestation"s);
                }
            }

            return attSignatureDigests;
        }

        static inline expected<AttestationApplicationIDType>
        _ASN1UnmarshalAttestAppID(const std::vector<uint8_t>& data) noexcept {

            if (data.empty()) {
                return unexpected("ASN1 parsing error of AttestationApplicationIDType in Android Key Attestation"s);
            }

            AttestationApplicationIDType attAppID{};
            auto p = data.data();
            auto end = p + data.size();
            auto retBytes = Util::Crypto::ASN1GetBytes(p);

            if (retBytes) {

                auto result = _ASN1UnmarshalAttestPackageInfos(retBytes.value());

                if (!result) {
                    return unexpected("ASN1 parsing error of AttestationApplicationIDType::PackageInfos in Android Key Attestation"s);
                }
                attAppID.PackageInfos = result.value();
            } else {
                return unexpected("ASN1 parsing error of AttestationApplicationIDType::PackageInfos in Android Key Attestation"s);
            }
            retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {

                auto result = _ASN1UnmarshalAttestSignatureDigests(retBytes.value());

                if (!result) {
                    return unexpected("ASN1 parsing error of AttestationApplicationIDType::SignatureDigests in Android Key Attestation"s);
                }
                attAppID.SignatureDigests = result.value();
            } else {
                return unexpected("ASN1 parsing error of AttestationApplicationIDType::SignatureDigests in Android Key Attestation"s);
            }

            return attAppID;
        }

        static inline expected<RootOfTrustType>
        _ASN1UnmarshalRootOfTrust(const std::vector<uint8_t>& data) noexcept {

            if (data.empty()) {
                return unexpected("ASN1 parsing error of RootOfTrustType in Android Key Attestation"s);
            }

            RootOfTrustType rootOfTrust{};
            auto p = data.data();
            auto end = p + data.size();
            auto retBytes = Util::Crypto::ASN1GetBytes(p);

            if (retBytes) {
                rootOfTrust.VerifiedBootKey = retBytes.value();
            } else {
                return unexpected("ASN1 parsing error of RootOfTrustType::VerifiedBootKey in Android Key Attestation"s);
            }
            auto retInt = p < end ? Util::Crypto::ASN1GetInt(p) : unexpected(""s);

            if (retInt) {
                rootOfTrust.DeviceLocked = retInt.value() != 0;
            } else {
                return unexpected("ASN1 parsing error of RootOfTrustType::DeviceLocked in Android Key Attestation"s);
            }
            retInt = p < end ? Util::Crypto::ASN1GetInt(p) : unexpected(""s);

            if (retInt) {
                rootOfTrust.VerifiedBootState = static_cast<VerifiedBootStateType>(retInt.value());
            } else {
                return unexpected("ASN1 parsing error of RootOfTrustType::VerifiedBootState in Android Key Attestation"s);
            }
            retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {
                rootOfTrust.VerifiedBootHash = retBytes.value();
            } else {
                return unexpected("ASN1 parsing error of RootOfTrustType::VerifiedBootHash in Android Key Attestation"s);
            }

            return rootOfTrust;
        }

        static inline expected<AuthorizationListType>
        _ASN1UnmarshalAuthorizationList(const std::vector<uint8_t>& data) noexcept {

            AuthorizationListType authList{};
            auto p = data.data();
            auto asn1MapResult = Util::Crypto::ASN1GetMap(p, data.size());

            if (!asn1MapResult) {
                return unexpected("ASN1 map parsing error"s);
            }
            auto asn1Map = asn1MapResult.value();
            using ALT = AuthorizationListType;

            ASSIGN_ASN1_FIELD(authList.Purpose,                     ALT::PURPOSE_TAG,                        _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.Algorithm,                   ALT::ALGORITHM_TAG,                      _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.KeySize,                     ALT::KEY_SIZE_TAG,                       _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.Digest,                      ALT::DIGEST_TAG,                         _ToInt32Set,                 std::nullopt)
            ASSIGN_ASN1_FIELD(authList.Padding,                     ALT::PADDING_TAG,                        _ToInt32Set,                 std::nullopt)
            ASSIGN_ASN1_FIELD(authList.EcCurve,                     ALT::EC_CURVE_TAG,                       _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.RsaPublicExponent,           ALT::RSA_PUBLIC_EXPONENT_TAG,            _ToInt64,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.RollbackResistance,          ALT::ROLLBACK_RESISTANCE_TAG,            _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.ActiveDateTime,              ALT::ACTIVE_DATE_TIME_TAG,               _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.OriginationExpireDateTime,   ALT::ORIGINATION_DATE_TIME_TAG,          _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.UsageExpireDateTime,         ALT::USAGE_EXPIRE_DATE_TIME_TAG,         _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.NoAuthRequired,              ALT::NO_AUTH_REQUIRED_TAG,               _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.UserAuthType,                ALT::USER_AUTH_TYPE_TAG,                 _ToIntEnum<UserAuthType>,    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AuthTimeout,                 ALT::AUTH_TIMEOUT_TAG,                   _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AllowWhileOnBody,            ALT::ALLOW_WHILE_ON_BODY_TAG,            _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.TrustedUserPresenceRequired, ALT::TRUSTED_USER_PRESENCE_REQUIRED_TAG, _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.TrustedConfirmationRequired, ALT::TRUSTED_CONFIRMATION_REQUIRED_TAG,  _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.UnlockedDeviceRequired,      ALT::UNLOCKED_DEVICE_REQUIRED_TAG,       _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.AllApplications,             ALT::ALL_APPLICATIONS_TAG,               _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.ApplicationID,               ALT::APPLICATION_ID_TAG,                 _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.CreationDateTime,            ALT::CREATION_DATE_TIME_TAG,             _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.Origin,                      ALT::ORIGIN_TAG,                         _ToIntEnum<KmKeyOriginType>, std::nullopt)
            ASSIGN_ASN1_FIELD(authList.RollbackResistant,           ALT::ROLLBACK_RESISTANT_TAG,             _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.RootOfTrust,                 ALT::ROOT_OF_TRUST_TAG,                  _ASN1UnmarshalRootOfTrust,   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.OsVersion,                   ALT::OS_VERSION_TAG,                     _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.OsPatchLevel,                ALT::OS_PATCH_LEVEL_TAG,                 _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationApplicationID,    ALT::ATTESTATION_APPLICATION_ID_TAG,     _ASN1UnmarshalAttestAppID,   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDBrand,          ALT::ATTESTATION_ID_BRAND_TAG,           _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDDevice,         ALT::ATTESTATION_ID_DEVICE_TAG,          _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDProduct,        ALT::ATTESTATION_ID_PRODUCT_TAG,         _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDSerial,         ALT::ATTESTATION_ID_SERIAL_TAG,          _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDImei,           ALT::ATTESTATION_ID_IMEI_TAG,            _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDMeid,           ALT::ATTESTATION_ID_MEID_TAG,            _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDManufacturer,   ALT::ATTESTATION_ID_MANUFACTURER_TAG,    _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.AttestationIDModel,          ALT::ATTESTATION_ID_MODEL_TAG,           _Identity,                   std::nullopt)
            ASSIGN_ASN1_FIELD(authList.VendorPatchLevel,            ALT::VENDOR_PATCH_LEVEL_TAG,             _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.BootPatchLevel,              ALT::BOOT_PATCH_LEVEL_TAG,               _ToInt32,                    std::nullopt)
            ASSIGN_ASN1_FIELD(authList.DeviceUniqueAttestation,     ALT::DEVICE_UNIQUE_ATTESTATION_TAG,      _ToBool,                            false)
            ASSIGN_ASN1_FIELD(authList.IdentityCredentialKey,       ALT::IDENTITY_CREDENTIAL_KEY_TAG,        _ToBool,                            false)

            return authList;
        }

        static inline expected<KeyDescriptionType>
        _ASN1UnmarshalKeyDescription(const std::vector<uint8_t>& data) noexcept {

            if (data.size() < 4) {
                return unexpected("ASN1 parsing error of KeyDescriptionType in Android Key Attestation"s);
            }

            KeyDescriptionType keyDesc{};
            auto p = data.data();
            auto end = p + data.size();
            auto retSequence = Util::Crypto::ASN1GetSequence(p);

            if (!retSequence || p + retSequence.value() != end) {
                return unexpected("ASN1 parsing error of KeyDescriptionType::AttestationVersion in Android Key Attestation"s);
            }
            auto retInt = Util::Crypto::ASN1GetInt(p);

            if (retInt) {
                keyDesc.AttestationVersion = retInt.value();
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::AttestationVersion in Android Key Attestation"s);
            }
            retInt = p < end ? Util::Crypto::ASN1GetInt(p) : unexpected(""s);

            if (retInt) {
                keyDesc.AttestationSecurityLevel = static_cast<SecurityLevelType>(retInt.value());
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::AttestationSecurityLevel in Android Key Attestation"s);
            }
            retInt = p < end ? Util::Crypto::ASN1GetInt(p) : unexpected(""s);

            if (retInt) {
                keyDesc.KeymasterVersion = retInt.value();
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::KeymasterVersion in Android Key Attestation"s);
            }
            retInt = p < end ? Util::Crypto::ASN1GetInt(p) : unexpected(""s);

            if (retInt) {
                keyDesc.KeymasterSecurityLevel = static_cast<SecurityLevelType>(retInt.value());
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::KeymasterSecurityLevel in Android Key Attestation"s);
            }
            auto retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {
                keyDesc.AttestationChallenge = retBytes.value();
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::AttestationChallenge in Android Key Attestation"s);
            }
            retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {
                keyDesc.UniqueID = retBytes.value();
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::UniqueID in Android Key Attestation"s);
            }
            retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {

                auto ret = _ASN1UnmarshalAuthorizationList(retBytes.value());

                if (ret) {
                    keyDesc.SoftwareEnforced = ret.value();
                } else {
                    return unexpected("ASN1 parsing error of KeyDescriptionType::SoftwareEnforced in Android Key Attestation"s);
                }
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::SoftwareEnforced in Android Key Attestation"s);
            }
            retBytes = p < end ? Util::Crypto::ASN1GetBytes(p) : unexpected(""s);

            if (retBytes) {

                auto ret = _ASN1UnmarshalAuthorizationList(retBytes.value());

                if (ret) {
                    keyDesc.TeeEnforced = ret.value();
                } else {
                    return unexpected("ASN1 parsing error of KeyDescriptionType::TeeEnforced in Android Key Attestation"s);
                }
            } else {
                return unexpected("ASN1 parsing error of KeyDescriptionType::TeeEnforced in Android Key Attestation"s);
            }

            return keyDesc;
        }

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

                constexpr auto ID_FIDO = "1.3.6.1.4.1.11129.2.1.1"; //asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17};
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
                auto decodedResult = _ASN1UnmarshalKeyDescription(attExtBytes);

                if (!decodedResult) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to parse Android Key attestation certificate extensions"));
                }
                auto decoded = decodedResult.value();

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
                if ((decoded.SoftwareEnforced.Origin && decoded.SoftwareEnforced.Origin.value() != KmKeyOriginType::Generated) ||
                    (decoded.TeeEnforced.Origin && decoded.TeeEnforced.Origin.value() != KmKeyOriginType::Generated) ||
                    (!decoded.SoftwareEnforced.Origin && !decoded.TeeEnforced.Origin)) {
                    return unexpected(ErrAttestationFormat().WithDetails("Attestation certificate extensions contains authorization list with origin not equal KM_ORIGIN_GENERATED"));
                }

                // The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN. (which == 2)
                if ((!decoded.SoftwareEnforced.Purpose || 
                     ((decoded.SoftwareEnforced.Purpose.value() & static_cast<int32_t>(KmPurposeType::Sign)) == 0)) && 
                    (!decoded.TeeEnforced.Purpose || 
                     ((decoded.TeeEnforced.Purpose.value() & static_cast<int32_t>(KmPurposeType::Sign)) == 0))) {
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
