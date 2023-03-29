//
//  TPM.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_TPM_IPP
#define WEBAUTHN_UTIL_TPM_IPP

#include "tpm2-tss/tss2/tss2_mu.h"
#include "../Core.ipp"
#include "Crypto.ipp"
#include "StringCompare.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::TPM {

    using namespace std::string_literals;

    /*enum class EC2CurveType : uint16_t {

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
    };*/

    struct PointType {

        std::vector<uint8_t> XRaw;
        std::vector<uint8_t> YRaw;
    };

    struct ECCParametersType {

        TPM2_ECC_CURVE CurveID;
        PointType      Point;
    };

    struct RSAParametersType {

        std::vector<uint8_t> ModulusRaw;
        uint32_t             Exponent;
    };

    struct PublicAreaInfoType {

        TPMI_ALG_PUBLIC      Type;
        TPMI_ALG_HASH        NameAlg;
        ECCParametersType    ECCParameters;
        RSAParametersType    RSAParameters;
        TPMU_PUBLIC_ID       ID;
    };

    struct CertInfoType {

        TPMI_ST_ATTEST       Type;
        TPMS_CERTIFY_INFO    AttestedCertifyInfo;
        std::vector<uint8_t> ExtraData;
    };

    inline expected<PublicAreaInfoType>
    DecodePublicArea(const std::vector<uint8_t>& publicAreaData) noexcept {

        size_t offset = 0UL;
        TPMT_PUBLIC pub{};
        auto result = Tss2_MU_TPMT_PUBLIC_Unmarshal(publicAreaData.data(), publicAreaData.size(), &offset, &pub);

        if (result != TSS2_RC_SUCCESS) {
            return unexpected(ErrorType("Could not decode public area data"s));
        }
        auto isECC = false;
        auto isRSA = false;

        switch (pub.type) {

            case TPM2_ALG_RSA:    ;
            case TPM2_ALG_RSAES:  ;
            case TPM2_ALG_RSAPSS: ;
            case TPM2_ALG_RSASSA: isRSA = true;
                break;

            case TPM2_ALG_ECC:   ;
            case TPM2_ALG_ECDAA: ;
            case TPM2_ALG_ECDH:  ;
            case TPM2_ALG_ECDSA: isECC = true;
                break;

            default: return unexpected(ErrorType("Unsupported algorithm"s));
        }

        PublicAreaInfoType publicAreaInfo{
            .Type          = pub.type,
            .NameAlg       = pub.nameAlg,
            .ECCParameters = isECC ? ECCParametersType{
                .CurveID = pub.parameters.eccDetail.curveID,
                .Point   = PointType{
                    .XRaw = std::vector<uint8_t>(pub.unique.ecc.x.buffer, pub.unique.ecc.x.buffer + pub.unique.ecc.x.size),
                    .YRaw = std::vector<uint8_t>(pub.unique.ecc.y.buffer, pub.unique.ecc.y.buffer + pub.unique.ecc.y.size)
                }
            } : ECCParametersType{},
            .RSAParameters = isRSA ? RSAParametersType{
                .ModulusRaw = std::vector(pub.unique.rsa.buffer, pub.unique.rsa.buffer + pub.unique.rsa.size),
                .Exponent   = (pub.parameters.rsaDetail.exponent != 0 ? pub.parameters.rsaDetail.exponent : UINT32(65537))
            } : RSAParametersType{}
        };
        std::memcpy(&publicAreaInfo.ID, &pub.unique, sizeof(pub.unique));

        return publicAreaInfo;
    }

    inline expected<CertInfoType>
    DecodeAttestationData(const std::vector<uint8_t>& certInfoData) noexcept {

        size_t offset = 0UL;
        TPMS_ATTEST attest{};
        auto result = Tss2_MU_TPMS_ATTEST_Unmarshal(certInfoData.data(), certInfoData.size(), &offset, &attest);

        if (result != TSS2_RC_SUCCESS) {
            return unexpected(ErrorType("Could not decode attestation data"s));
        }
        
        if (attest.magic != TPM2_GENERATED_VALUE) {
            return unexpected(ErrorType("Magic number not set to TPM2_GENERATED_VALUE"s));
        }

        CertInfoType certInfo{
            .Type =  attest.type,
            .AttestedCertifyInfo = TPMS_CERTIFY_INFO{
                .name = TPM2B_NAME{
                    .size = attest.attested.certify.name.size
                },
                .qualifiedName = TPM2B_NAME {
                    .size = attest.attested.certify.qualifiedName.size
                }
            },
            .ExtraData = std::vector<uint8_t>(attest.extraData.buffer, attest.extraData.buffer + attest.extraData.size)
        };
        std::memcpy(certInfo.AttestedCertifyInfo.name.name, 
                    attest.attested.certify.name.name,
                    attest.attested.certify.name.size);
        std::memcpy(certInfo.AttestedCertifyInfo.qualifiedName.name, 
                    attest.attested.certify.qualifiedName.name,
                    attest.attested.certify.qualifiedName.size);

        return certInfo;
    }

    inline expected<bool>
    NameMatchesPublicArea(const TPMS_CERTIFY_INFO& attestedCertifyInfo, const PublicAreaInfoType& publicAreaInfo) noexcept {

        auto asDigest = *reinterpret_cast<const TPMU_NAME*>(attestedCertifyInfo.name.name);
        auto attHashAlg = asDigest.digest.hashAlg;

        if (attHashAlg == publicAreaInfo.NameAlg) {

            const BYTE* nameDigest = asDigest.digest.digest.sha;

            switch (attHashAlg) {

                case TPM2_ALG_SHA1: nameDigest = asDigest.digest.digest.sha1;
                    break;

                case TPM2_ALG_SHA256: nameDigest = asDigest.digest.digest.sha256;
                    break;

                case TPM2_ALG_SHA384: nameDigest = asDigest.digest.digest.sha384;
                    break;

                case TPM2_ALG_SHA512: nameDigest = asDigest.digest.digest.sha512;
                    break;

                case TPM2_ALG_SM3_256: nameDigest = asDigest.digest.digest.sm3_256;
                    //return unexpected(ErrorType("SM3-256 hash algorithm of attested is not supported"s));
                    break;

                default: unexpected(ErrorType("The hash algorithm of attested is unknown"s));
            }
            auto nameDigestSize = sizeof(nameDigest);

            if (publicAreaInfo.ID.keyedHash.size == nameDigestSize) {
                return Util::StringCompare::ConstantTimeEqual(publicAreaInfo.ID.keyedHash.buffer, nameDigest, nameDigestSize);
            } else {
                return unexpected(ErrorType("The hash algorithm sizes of attested and public area info do not match"s));
            }
        } else {
            return unexpected(ErrorType("The hash algorithm ids of attested and public area info do not match"s));
        }

        return false;
    }
} // namespace WebAuthN::Util::TPM

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_TPM_IPP */
