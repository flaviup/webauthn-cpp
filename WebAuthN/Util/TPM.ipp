//
//  TPM.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_TPM_IPP
#define WEBAUTHN_UTIL_TPM_IPP

#include "../Core.ipp"
#include "../Util/Base64.ipp"
#include "TPMTypes.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::TPM {

    using namespace std::string_literals;

#pragma GCC visibility push(hidden)

    namespace {

        enum BlobType : int {
            InitState,
            Last
        };
        
        static inline constexpr auto _INITSTATE_START_TAG = "-----BEGIN INITSTATE-----";
        static inline constexpr auto _INITSTATE_END_TAG   = "-----END INITSTATE-----";

        static inline constexpr struct TagsAndIndicesType {

            const char* StartTag;
            const char* EndTag;
        } _TAGS_AND_INDICES[] = {
            [BlobType::InitState] = {
                .StartTag = _INITSTATE_START_TAG,
                .EndTag   = _INITSTATE_END_TAG
            }
        };

        static inline expected<std::string>
        _GetPlaintext(const char* stream,
                      const char* startTag,
                      const char* endTag) noexcept {

            auto start = strstr(stream, startTag);
            decltype(start) end = nullptr;

            if (start) {

                start += strlen(startTag);

                while (isspace((int)*start)) ++start;
                end = strstr(start, endTag);

                if (end) {

                    --end;
                    return Base64_Decode(start, end - start, true, false);
                }
            }

            return ""s;
        }
    } // namespace

#pragma GCC visibility pop

    enum class EC2CurveType : uint16_t {

        None      = 0x0000,
        NIST_P192 = 0x0001,
        NIST_P224 = 0x0002,
        NIST_P256 = 0x0003,
        NIST_P384 = 0x0004,
        NIST_P521 = 0x0005,
        BN_P256   = 0x0010,
        BN_P638   = 0x0011,
        SM2_P256  = 0x0020
    };

    enum class STType : uint16_t {

        RSPCommand         = 0x00C4,
        Null               = 0x8000,
        NoSessions         = 0x8001,
        Sessions           = 0x8002,
        AttestNV           = 0x8014,
        AttestCommandAudit = 0x8015,
        AttestSessionAudit = 0x8016,
        AttestCertify      = 0x8017,
        AttestQuote        = 0x8018,
        AttestTime         = 0x8019,
        AttestCreation     = 0x801A,
        AttestNVDigest     = 0x801C,
        Creation           = 0x8021,
        Verified           = 0x8022,
        AuthSecret         = 0x8023,
        HashCheck          = 0x8024,
        AuthSigned         = 0x8025,
        FUManifest         = 0x8029
    };

    struct PointType {

        std::vector<uint8_t> XRaw;
        std::vector<uint8_t> YRaw;
    };

    struct ECCParametersType {

        EC2CurveType CurveID;
        PointType Point;
    };

    struct RSAParametersType {

        std::vector<uint8_t> ModulusRaw;
        uint32_t Exponent;
    };

    struct PublicAreaInfoType {

        ECCParametersType ECCParameters;
        RSAParametersType RSAParameters;
    };

    struct AttestedCertifyInfoType {

        std::string Name;
    };

    struct CertInfoType {

        STType Type;
        AttestedCertifyInfoType AttestedCertifyInfo;
        std::vector<uint8_t> ExtraData;
    };

    inline expected<std::string>
    DecodeBlob(const std::string& blob, BlobType type) noexcept {

        return _GetPlaintext(blob.data(),
                             _TAGS_AND_INDICES[type].StartTag,
                             _TAGS_AND_INDICES[type].EndTag);
    }

    inline expected<PublicAreaInfoType>
    DecodePublicArea(const std::vector<uint8_t>& publicAreaData) noexcept {

        return PublicAreaInfoType{};
    }

    inline expected<CertInfoType>
    DecodeAttestationData(const std::vector<uint8_t>& certInfoData) noexcept {

        return CertInfoType{};
    }

    inline expected<bool>
    NameMatchesPublicArea(const std::string& name, const std::vector<uint8_t>& publicAreaData) noexcept {

        return true;
    }
} // namespace WebAuthN::Util::TPM

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_TPM_IPP */
