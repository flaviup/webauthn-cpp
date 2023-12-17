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
        uint32_t             Exponent{0};
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
            return MakeError(ErrorType("Could not decode public area data"s));
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

            default: return MakeError(ErrorType("Unsupported algorithm"s));
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
                .Exponent   = (pub.parameters.rsaDetail.exponent != 0 ? pub.parameters.rsaDetail.exponent : static_cast<UINT32>(65537))
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
            return MakeError(ErrorType("Could not decode attestation data"s));
        }
        
        if (attest.magic != TPM2_GENERATED_VALUE) {
            return MakeError(ErrorType("Magic number not set to TPM2_GENERATED_VALUE"s));
        }

        CertInfoType certInfo{
            .Type =  attest.type,
            .AttestedCertifyInfo = TPMS_CERTIFY_INFO{
                .name = TPM2B_NAME{
                    .size = attest.attested.certify.name.size
                }
            },
            .ExtraData = std::vector<uint8_t>(attest.extraData.buffer, attest.extraData.buffer + attest.extraData.size)
        };
        std::memcpy(certInfo.AttestedCertifyInfo.name.name, 
                    attest.attested.certify.name.name,
                    attest.attested.certify.name.size);

        return certInfo;
    }

    inline expected<bool>
    NameMatchesPublicArea(const TPMS_CERTIFY_INFO& attestedCertifyInfo, TPMI_ALG_HASH nameAlg, const std::vector<uint8_t>& publicAreaData) noexcept {

        TPMI_ALG_HASH attHashAlg = TPMI_ALG_HASH(attestedCertifyInfo.name.name[0] << 8) + TPMI_ALG_HASH(attestedCertifyInfo.name.name[1]);

        if (attHashAlg == nameAlg) {

            std::vector<uint8_t> publicAreaHash{};

            switch (attHashAlg) {

                case TPM2_ALG_SHA1: publicAreaHash = Util::Crypto::SHA1(publicAreaData);
                    break;

                case TPM2_ALG_SHA256: publicAreaHash = Util::Crypto::SHA256(publicAreaData);
                    break;

                case TPM2_ALG_SHA384: publicAreaHash = Util::Crypto::SHA384(publicAreaData);
                    break;

                case TPM2_ALG_SHA512: publicAreaHash = Util::Crypto::SHA512(publicAreaData);
                    break;

                case TPM2_ALG_SM3_256: return MakeError(ErrorType("SM3-256 hash algorithm of attested is not supported"s));
                    break;

                default: MakeError(ErrorType("The hash algorithm of attested is unknown"s));
            }
            const auto SZ = sizeof(attHashAlg) + publicAreaHash.size();
            std::vector<uint8_t> attestedName(SZ);

            for (auto i = 0; i < sizeof(attHashAlg); ++i) {
                attestedName[i] = static_cast<uint8_t>((attHashAlg >> (8 * (sizeof(attHashAlg) - i - 1))) & 0xFF);
            }
            std::memcpy(attestedName.data() + sizeof(attHashAlg), publicAreaHash.data(), publicAreaHash.size());
            const auto NAME_DIGEST_SIZE = attestedCertifyInfo.name.size;

            if (NAME_DIGEST_SIZE == SZ) {
                return Util::StringCompare::ConstantTimeEqual(attestedCertifyInfo.name.name, attestedName.data(), SZ);
            } else {
                return MakeError(ErrorType("The hash algorithm sizes of attested and public area info do not match"s));
            }
        } else {
            return MakeError(ErrorType("The hash algorithm ids of attested and public area info do not match"s));
        }

        return false;
    }
} // namespace WebAuthN::Util::TPM

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_TPM_IPP */
