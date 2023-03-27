//
//  AttestationTPM.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ATTESTATION_TPM_IPP
#define WEBAUTHN_PROTOCOL_ATTESTATION_TPM_IPP

#include <functional>
#include <fmt/format.h>
#include "Attestation.ipp"
#include "../Util/Crypto.ipp"
#include "../Util/ASN1.ipp"
#include "../Util/TPM.ipp"
#include "WebAuthNCOSE/WebAuthNCOSE.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using namespace std::string_literals;
    using json = nlohmann::json;
    
    inline const auto TPM_ATTESTATION_KEY = "tpm"s;

#pragma GCC visibility push(hidden)

    namespace {

        namespace TPM = Util::TPM;
        namespace ASN1 = Util::ASN1;

        struct AttributeTypeAndValueType {

            std::string Type;
            std::vector<uint8_t> Value;
        };

        using RelativeDistinguishedNameSetType = std::vector<AttributeTypeAndValueType>;
        using RDNSequenceType = std::vector<RelativeDistinguishedNameSetType>;

        struct BasicConstraintsType {

            bool IsCA{false};   // `asn1:"optional"`
            int MaxPathLen{-1}; // `asn1:"optional,default:-1"`
        };

        struct TPMManufacturerInfoType {

            std::string ID;
            std::string Name;
            std::string Code;
        };

        static inline const TPMManufacturerInfoType _TPM_MANUFACTURERS[]{
            { "414D4400", "AMD",                               "AMD"  },
            { "41544D4C", "Atmel",                             "ATML" },
            { "4252434D", "Broadcom",                          "BRCM" },
            { "49424d00", "IBM",                               "IBM"  },
            { "49465800", "Infineon",                          "IFX"  },
            { "494E5443", "Intel",                             "INTC" },
            { "4C454E00", "Lenovo",                            "LEN"  },
            { "4E534D20", "National Semiconductor",            "NSM"  },
            { "4E545A00", "Nationz",                           "NTZ"  },
            { "4E544300", "Nuvoton Technology",                "NTC"  },
            { "51434F4D", "Qualcomm",                          "QCOM" },
            { "534D5343", "SMSC",                              "SMSC" },
            { "53544D20", "ST Microelectronics",               "STM"  },
            { "534D534E", "Samsung",                           "SMSN" },
            { "534E5300", "Sinosun",                           "SNS"  },
            { "54584E00", "Texas Instruments",                 "TXN"  },
            { "57454300", "Winbond",                           "WEC"  },
            { "524F4343", "Fuzhouk Rockchip",                  "ROCC" },
            { "FFFFF1D0", "FIDO Alliance Conformance Testing", "FIDO" },
        };

        static inline constexpr auto _NAME_TYPE_DN_TAG = 4;

        static inline const auto _TCG_KP_AIK_CERTIFICATE  = "2.23.133.8.3"s;
        static inline const auto _TCG_AT_TPM_MANUFACTURER = "2.23.133.2.1"s;
        static inline const auto _TCG_AT_TPM_MODEL        = "2.23.133.2.2"s;
        static inline const auto _TCG_AT_TPM_VERSION      = "2.23.133.2.3"s;

        static inline bool _IsValidTPMManufacturer(const std::string& ID) noexcept {

            return std::any_of(_TPM_MANUFACTURERS, 
                               _TPM_MANUFACTURERS + sizeof(_TPM_MANUFACTURERS), 
                               [&ID](const TPMManufacturerInfoType& tmi) { return tmi.ID == ID; });
        }

        static inline TPM2_ECC_CURVE _TPMCurveID(const WebAuthNCOSE::COSEEllipticCurveType curve) noexcept {

            switch (curve) {

                case WebAuthNCOSE::COSEEllipticCurveType::P256: return TPM2_ECC_NIST_P256;
                case WebAuthNCOSE::COSEEllipticCurveType::P384: return TPM2_ECC_NIST_P384;
                case WebAuthNCOSE::COSEEllipticCurveType::P521: return TPM2_ECC_NIST_P521;
                default:                                        return TPM2_ECC_NONE;
            }
        }

        static inline expected<std::vector<std::string>>
        _ASN1UnmarshalExtendedKeyUsage(const std::vector<uint8_t>& data) noexcept {

            auto p = data.data();
            auto end = p + data.size();
            auto retSequence = ASN1::GetSequence(p);

            if (!retSequence) {
                return unexpected(retSequence.error());
            } else if (p + retSequence.value() != end) {
                return unexpected(ErrorType("x509: trailing data present for extended key usage"s));
            }
            std::vector<std::string> eku{};

            while (p < end) {

                auto dataResult = ASN1::GetBytes(p);

                if (!dataResult) {
                    return unexpected(dataResult.error());
                }
                auto value = dataResult.value();
                eku.push_back(value.empty() ? ""s : std::string(value.data(), value.data() + value.size()));
            }
            
            return eku;
        }

        static inline expected<BasicConstraintsType>
        _ASN1UnmarshalBasicConstraints(const std::vector<uint8_t>& data) noexcept {

            auto p = data.data();
            auto end = p + data.size();
            auto retSet = ASN1::GetSet(p);

            if (!retSet) {
                return unexpected(retSet.error());
            } else if (p + retSet.value() != end) {
                return unexpected(ErrorType("AIK certificate basic constraints contains extra data"s));
            }
            auto retInt = ASN1::GetInt(p);

            if (retInt) {

                auto isCA = retInt.value() != 0;
                auto tag = 0;
                auto retInt = ASN1::GetInt(p, &tag);

                if (p != end) {
                    return unexpected(ErrorType("AIK certificate basic constraints contains extra data"s));
                }

                return BasicConstraintsType{
                    .IsCA = isCA,
                    .MaxPathLen = ((retInt && tag != V_ASN1_NULL) ? retInt.value() : -1)
                };
            }
            
            return BasicConstraintsType{
                .IsCA = false,
                .MaxPathLen = -1
            };
        }

        static inline expected<RDNSequenceType>
        _ASN1UnmarshalDeviceAttributes(const std::vector<uint8_t>& data) noexcept {

            auto p = data.data();
            auto end = p + data.size();
            auto retSequence = ASN1::GetSequence(p);

            if (!retSequence) {
                return unexpected(retSequence.error());
            } else if (p + retSequence.value() != end) {
                return unexpected(ErrorType("x509: trailing data present"s));
            }
            RDNSequenceType seq{};

            while (p < end) {

                auto retSet = ASN1::GetSet(p);

                if (!retSet) {
                    return unexpected(retSet.error());
                }
                auto end2 = p + retSet.value();
                RelativeDistinguishedNameSetType rdnSet{};

                while (p < end2) {

                    auto dataResult = ASN1::GetBytes(p);

                    if (!dataResult) {
                        return unexpected(dataResult.error());
                    }
                    auto type = dataResult.value();

                    if (p < end2) {
                        dataResult = ASN1::GetBytes(p);

                        if (!dataResult) {
                            return unexpected(dataResult.error());
                        }
                        rdnSet.push_back(AttributeTypeAndValueType{
                            .Type = type.empty() ? ""s : std::string(type.data(), type.data() + type.size()),
                            .Value = dataResult.value()
                        });
                        p = end2;
                    }
                }
                seq.push_back(rdnSet);
            }
            
            return seq;
        }

        //using SANParsingHandlerType = std::optional<ErrorType> (*)(int tag, const std::vector<uint8_t>& data);
        using SANParsingHandlerType = std::function<std::optional<ErrorType>(int,  const std::vector<uint8_t>&)>;

        static inline std::optional<ErrorType>
        _ForEachSAN(const std::vector<uint8_t>& extension, SANParsingHandlerType&& callback) noexcept {

            // RFC 5280, 4.2.1.6

            // SubjectAltName ::= GeneralNames
            //
            // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
            //
            // GeneralName ::= CHOICE {
            //      otherName                       [0]     OtherName,
            //      rfc822Name                      [1]     IA5String,
            //      dNSName                         [2]     IA5String,
            //      x400Address                     [3]     ORAddress,
            //      directoryName                   [4]     Name,
            //      ediPartyName                    [5]     EDIPartyName,
            //      uniformResourceIdentifier       [6]     IA5String,
            //      iPAddress                       [7]     OCTET STRING,
            //      registeredID                    [8]     OBJECT IDENTIFIER }

            auto p = extension.data();
            auto end = p + extension.size();
            auto retSequence = ASN1::GetSequence(p);

            if (!retSequence) {
                return retSequence.error();
            } else if (p + retSequence.value() != end) {
                return ErrorType("x509: trailing data after X.509 extension"s);
            }

            while (p < end) {

                auto tag = 0;
                auto dataResult = ASN1::GetBytes(p, &tag);

                if (!dataResult) {
                    return dataResult.error();
                }
                auto error = callback(tag, dataResult.value());

                if (error) {
                    return error;
                }
            }

            return std::nullopt;
        }

        static inline std::string _TrimPrefix(const std::string& str, const std::string& prefix) noexcept {

            auto prefixPos = str.find(prefix);
            return (prefixPos == 0) ? str.substr(prefix.size()): str;
        }

        static inline expected<std::tuple<std::string, std::string, std::string>>
        _ParseSANExtension(const std::vector<uint8_t>& value) noexcept {

            auto manufacturer = ""s, model = ""s, version = ""s;

            auto err = _ForEachSAN(value, [&manufacturer, &model, &version](int tag, const std::vector<uint8_t>& data) -> std::optional<ErrorType> {

                switch (tag) {

                    case _NAME_TYPE_DN_TAG: {

                        auto res = _ASN1UnmarshalDeviceAttributes(data);

                        if (!res) {
                            return res.error();
                        }
                        auto tpmDeviceAttributes = res.value();

                        for (const auto& rdn : tpmDeviceAttributes) {

                            if (rdn.empty()) {
                                continue;
                            }

                            for (const auto& atv : rdn) {

                                auto value = atv.Value.empty() ? ""s : std::string(atv.Value.data(), atv.Value.data() + atv.Value.size());

                                if (atv.Type == _TCG_AT_TPM_MANUFACTURER) {
                                    manufacturer = _TrimPrefix(value, "id:"s);
                                }

                                if (atv.Type == _TCG_AT_TPM_MODEL) {
                                    model = value;
                                }

                                if (atv.Type == _TCG_AT_TPM_VERSION) {
                                    version = _TrimPrefix(value, "id:"s);
                                }
                            }
                        }
                    }
                }

                return std::nullopt;
            });

            if (err) {
                return unexpected(err.value());
            }

            return std::make_tuple(manufacturer, model, version);
        }

        static inline expected<std::tuple<std::string, std::optional<json>>>
        _VerifyTPMFormat(const AttestationObjectType& att, const std::vector<uint8_t>& clientDataHash) noexcept {

            // Given the verification procedure inputs attStmt, authenticatorData
            // and clientDataHash, the verification procedure is as follows

            // Verify that attStmt is valid CBOR conforming to the syntax defined
            // above and perform CBOR decoding on it to extract the contained fields

            if (att.AttStatement) {

                auto atts = att.AttStatement.value();

                if (atts.find("ver") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving ver value"s));
                }
                auto ver = atts["ver"].get<std::string>();

                if (ver != "2.0"s) {
                    return unexpected(ErrAttestationFormat().WithDetails("WebAuthn only supports TPM 2.0 currently"s));
                }

                if (atts.find("alg") == atts.cend()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving alg value"s));
                }
                auto alg = atts["alg"].get<int64_t>();

                if (atts.find("x5c") == atts.cend()) { // If x5c is not present, return an error
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving x5c value"s));
                }
                auto x5c = atts["x5c"]; // If x5c is present, this indicates that the attestation type is not ECDAA.

                if (x5c.empty()) {
                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"s));
                }

                if (atts.find("ecdaaKeyId") == atts.cend() || !atts["ecdaaKeyId"].is_binary()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving ecdaaKeyId value"s));
                }

                if (atts.find("sig") == atts.cend() || !atts["sig"].is_binary()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving sig value"s));
                }
                auto signature = atts["sig"].get_binary();

                if (atts.find("certInfo") == atts.cend() || !atts["certInfo"].is_binary()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving certInfo value"s));
                }
                auto certInfoData = atts["certInfo"].get_binary();

                if (atts.find("pubArea") == atts.cend() || !atts["pubArea"].is_binary()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Error retrieving pubArea value"s));
                }
                auto pubArea = atts["pubArea"].get_binary();

                // Verify that the public key specified by the parameters and unique fields of pubArea
                // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
                auto pubAreaDecodeResult = TPM::DecodePublicArea(pubArea);

                if (!pubAreaDecodeResult) {
                    return unexpected(ErrAttestationFormat().WithDetails("Unable to decode TPMT_PUBLIC in attestation statement"s));
                }
                auto pubAreaInfo = pubAreaDecodeResult.value();
                auto ok = WebAuthNCOSE::ParsePublicKey(att.AuthData.AttData.CredentialPublicKey);

                if (!ok) {
                    return unexpected(ErrInvalidAttestation().WithDetails(fmt::format("Error parsing the public key: {}", std::string(ok.error()))));
                }
                auto success = false;
                auto pubKey = ok.value();
                auto vpk = WebAuthNCOSE::KeyCast(pubKey, success);

                if (!success) {
                    return unexpected(ErrUnsupportedKey());
                }
                const auto& key = vpk.Value;
                auto keyType = static_cast<WebAuthNCOSE::COSEKeyType>(key.KeyType);

                switch (keyType) {

                    case WebAuthNCOSE::COSEKeyType::EllipticKey: {

                        const auto& ec2Key = dynamic_cast<const WebAuthNCOSE::EC2PublicKeyDataType&>(key);

                        if (!ec2Key.Curve || !ec2Key.XCoord || !ec2Key.YCoord ||
                            pubAreaInfo.ECCParameters.CurveID != _TPMCurveID(static_cast<WebAuthNCOSE::COSEEllipticCurveType>(ec2Key.Curve.value())) ||
                            pubAreaInfo.ECCParameters.Point.XRaw != ec2Key.XCoord.value() ||
                            pubAreaInfo.ECCParameters.Point.YRaw != ec2Key.YCoord.value()) {

                            return unexpected(ErrAttestationFormat().WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey"s));
                        }
                    }

                    case WebAuthNCOSE::COSEKeyType::RSAKey: {

                        const auto& rsaKey = dynamic_cast<const WebAuthNCOSE::RSAPublicKeyDataType&>(key);
                        // TBD: Check byte order of the exponent: 0 1 2, or 2 1 0 (also check in WebAuthNCOSE::RSAPublicKeyDataType::Verify)
                        auto exp = (rsaKey.Exponent && rsaKey.Exponent.value().size() > 2) ? static_cast<int32_t>(static_cast<uint32_t>(rsaKey.Exponent.value()[2]) |
                                                                                             (static_cast<uint32_t>(rsaKey.Exponent.value()[1]) << 8) |
                                                                                             (static_cast<uint32_t>(rsaKey.Exponent.value()[0]) << 16)) : 
                                                                                             uint32_t(0);

                        if (!rsaKey.Modulus || !rsaKey.Exponent || rsaKey.Exponent.value().size() < 3 ||
                            pubAreaInfo.RSAParameters.ModulusRaw != rsaKey.Modulus.value() ||
                            pubAreaInfo.RSAParameters.Exponent != exp) {

                            return unexpected(ErrAttestationFormat().WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey"s));
                        }
                    }

                    default:
                        return unexpected(ErrUnsupportedKey());
                }
                std::vector<uint8_t> attToBeSigned(att.RawAuthData.size() + clientDataHash.size());
                std::memcpy(attToBeSigned.data(), att.RawAuthData.data(), att.RawAuthData.size());
                std::memcpy(attToBeSigned.data() + att.RawAuthData.size(), clientDataHash.data(), clientDataHash.size());

                // Validate that certInfo is valid:
                // 1/4 Verify that magic is set to TPM2_GENERATED_VALUE, handled here
                auto certInfoResult = TPM::DecodeAttestationData(certInfoData);

                if (!certInfoResult) {
                    return unexpected(certInfoResult.error());
                }
                auto certInfo = certInfoResult.value();

                // 2/4 Verify that type is set to TPM2_ST_ATTEST_CERTIFY.
                if (certInfo.Type != TPM2_ST_ATTEST_CERTIFY) {
                    return unexpected(ErrAttestationFormat().WithDetails("Type is not set to TPM_ST_ATTEST_CERTIFY"s));
                }

                // 3/4 Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
                auto coseAlg = static_cast<WebAuthNCOSE::COSEAlgorithmIdentifierType>(alg);
                auto hasher = WebAuthNCOSE::HasherFromCOSEAlg(coseAlg);

                if (certInfo.ExtraData != hasher(attToBeSigned)) {
                    return unexpected(ErrAttestationFormat().WithDetails("ExtraData is not set to hash of attToBeSigned"s));
                }

                // 4/4 Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in
                // [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea,
                // as computed using the algorithm in the nameAlg field of pubArea
                // using the procedure specified in [TPMv2-Part1] section 16.
                auto matchResult = TPM::NameMatchesPublicArea(certInfo.AttestedCertifyInfo, pubAreaInfo);

                if (!matchResult) {
                    return unexpected(matchResult.error());
                }

                if (!matchResult.value()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Hash value mismatch attested and pubArea"s));
                }

                // Note that the remaining fields in the "Standard Attestation Structure"
                // [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion
                // are ignored. These fields MAY be used as an input to risk engines.

                // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
                std::vector<uint8_t> aikCertBytes{};

                try {
                    aikCertBytes = x5c[0].get_binary();
                } catch (const std::exception&) {
                    return unexpected(ErrAttestation().WithDetails("Error getting certificate from x5c cert chain"s));
                }
                auto aikCertResult = Util::Crypto::ParseCertificate(aikCertBytes);

                if (!aikCertResult) {
                    return unexpected(ErrAttestation().WithDetails(fmt::format("Error parsing certificate from ASN.1 data: {}", std::string(aikCertResult.error()))));
                }
                auto aikCert = aikCertResult.value();
                auto sigAlg = WebAuthNCOSE::SigAlgFromCOSEAlg(coseAlg);
                auto signatureCheckResult = Util::Crypto::CheckSignature(aikCertBytes, 
                                                                        WebAuthNCOSE::SignatureAlgorithmTypeToString(sigAlg), 
                                                                        certInfoData, 
                                                                        signature);

                if (!signatureCheckResult || !signatureCheckResult.value()) {
                    return unexpected(ErrInvalidAttestation().WithDetails(signatureCheckResult ? "Signature validation error"s : fmt::format("Signature validation error: {}", std::string(signatureCheckResult.error()))));
                }

                // Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements

                // 1/6 Version MUST be set to 3.
                if (aikCert.Version != 3L) {
                    return unexpected(ErrAttestationFormat().WithDetails("AIK certificate version must be 3"s));
                }

                // 2/6 Subject field MUST be set to empty.
                if (!aikCert.Subject.Country.empty() ||
                    !aikCert.Subject.Organization.empty() ||
                    !aikCert.Subject.OrganizationalUnit.empty() ||
                    !aikCert.Subject.CommonName.empty()) {

                    return unexpected(ErrAttestationFormat().WithDetails("AIK certificate subject must be empty"s));
                }

                // 3/6 The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9{}
                std::string manufacturer, model, version;

                for (const auto& ext : aikCert.Extensions) {

                    if (ext.ID == "2.5.29.17"s) {

                        auto sanParseResult = _ParseSANExtension(ext.Value);

                        if (!sanParseResult) {
                            return unexpected(sanParseResult.error());
                        }
                    }
                }

                if (manufacturer.empty() || model.empty() || version.empty()) {
                    return unexpected(ErrAttestationFormat().WithDetails("Invalid SAN data in AIK certificate"s));
                }

                if (!_IsValidTPMManufacturer(manufacturer)) {
                    return unexpected(ErrAttestationFormat().WithDetails("Invalid TPM manufacturer"s));
                }

                // 4/6 The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
                auto ekuValid = false;

                for (const auto& ext : aikCert.Extensions) {

                    if (ext.ID == "2.5.29.37") {

                        auto result =_ASN1UnmarshalExtendedKeyUsage(ext.Value);

                        if (!result) {
                            return unexpected(ErrAttestationFormat().WithDetails("AIK certificate EKU missing 2.23.133.8.3"s));
                        }
                        auto eku = result.value();

                        if (eku.empty() || eku[0] != _TCG_KP_AIK_CERTIFICATE) {
                            return unexpected(ErrAttestationFormat().WithDetails("AIK certificate EKU missing 2.23.133.8.3"s));
                        }
                        ekuValid = true;
                    }
                }

                if (!ekuValid) {
                    return unexpected(ErrAttestationFormat().WithDetails("AIK certificate missing EKU"s));
                }

                // 5/6 The Basic Constraints extension MUST have the CA component set to false.
                BasicConstraintsType constraints{};

                for (const auto& ext : aikCert.Extensions) {

                    if (ext.ID == "2.5.29.19") {

                        auto result = _ASN1UnmarshalBasicConstraints(ext.Value);

                        if (!result) {
                            return unexpected(ErrAttestationFormat().WithDetails(fmt::format("AIK certificate basic constraints malformed {}", std::string(result.error()))));
                        }
                        constraints = result.value();
                    }
                }

                // 6/6 An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point
                // extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available
                // through metadata services. See, for example, the FIDO Metadata Service.
                if (constraints.IsCA) {
                    return unexpected(ErrAttestationFormat().WithDetails("AIK certificate basic constraints missing or CA is true"s));
                }

                // If successful, return attestation type AttCA with the attestation trust path set to x5c.
                return std::make_tuple(json(Metadata::AuthenticatorAttestationType::AttCA).get<std::string>(), std::optional<json>{x5c});
            }

            return unexpected(ErrAttestationFormat().WithDetails("No attestation statement provided"s));
        }
    } // namespace

#pragma GCC visibility pop

    inline void RegisterTPMAttestation() noexcept {

        RegisterAttestationFormat(TPM_ATTESTATION_KEY, _VerifyTPMFormat);
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif // WEBAUTHN_PROTOCOL_ATTESTATION_TPM_IPP
