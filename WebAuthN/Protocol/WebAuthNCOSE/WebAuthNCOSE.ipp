//
//  WebAuthNCOSE.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP
#define WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP

#include <algorithm>
#include <any>
#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>
//#include <openssl/param_build.h>

#include "../../Core.ipp"
#include "../../Util/Crypto.ipp"
#include "../WebAuthNCBOR/WebAuthNCBOR.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol::WebAuthNCOSE {

    using namespace std::string_literals;
    using json = nlohmann::json;

    // Consts

    inline const auto KEY_CANNOT_DISPLAY = "Cannot display key"s;

    // Enums

    // COSEAlgorithmIdentifierType is a number identifying a cryptographic algorithm. The algorithm identifiers SHOULD be values
    // registered in the IANA COSE Algorithms registry [https://www.w3.org/TR/webauthn/#biblio-iana-cose-algs-reg], for
    // instance, -7 for "ES256" and -257 for "RS256".
    //
    // Specification: §5.8.5. Cryptographic Algorithm Identifier (https://www.w3.org/TR/webauthn/#sctn-alg-identifier)
    enum class COSEAlgorithmIdentifierType : int {

        // AlgES256 ECDSA with SHA-256.
        AlgES256 = -7,
        // AlgES384 ECDSA with SHA-384.
        AlgES384 = -35,
        // AlgES512 ECDSA with SHA-512.
        AlgES512 = -36,
        // AlgRS1 RSASSA-PKCS1-v1_5 with SHA-1.
        AlgRS1 = -65535,
        // AlgRS256 RSASSA-PKCS1-v1_5 with SHA-256.
        AlgRS256 = -257,
        // AlgRS384 RSASSA-PKCS1-v1_5 with SHA-384.
        AlgRS384 = -258,
        // AlgRS512 RSASSA-PKCS1-v1_5 with SHA-512.
        AlgRS512 = -259,
        // AlgPS256 RSASSA-PSS with SHA-256.
        AlgPS256 = -37,
        // AlgPS384 RSASSA-PSS with SHA-384.
        AlgPS384 = -38,
        // AlgPS512 RSASSA-PSS with SHA-512.
        AlgPS512 = -39,
        // AlgEdDSA EdDSA.
        AlgEdDSA = -8,
        // AlgES256K is ECDSA using secp256k1 curve and SHA-256.
        AlgES256K = -47
    };

    inline constexpr bool operator <(const enum COSEAlgorithmIdentifierType selfValue, const enum COSEAlgorithmIdentifierType inValue) noexcept {

        return static_cast<int>(selfValue) < static_cast<int>(inValue);
    }

    inline constexpr bool operator >(const enum COSEAlgorithmIdentifierType selfValue, const enum COSEAlgorithmIdentifierType inValue) noexcept {

        return static_cast<int>(selfValue) > static_cast<int>(inValue);
    }

    inline void from_json(const json& j, COSEAlgorithmIdentifierType& coseAlgorithmIdentifier) {

        auto value = j.get<int>();
        coseAlgorithmIdentifier = static_cast<COSEAlgorithmIdentifierType>(value);
    }

    inline void to_json(json& j, const COSEAlgorithmIdentifierType& coseAlgorithmIdentifier) {

        j = json{
            static_cast<int>(coseAlgorithmIdentifier)
        };
    }

    inline std::optional<COSEAlgorithmIdentifierType> COSEAlgorithmIdentifierTypeFromNID(int nid) noexcept {

        switch (nid) {

            case NID_ecdsa_with_SHA256:       return COSEAlgorithmIdentifierType::AlgES256;
            case NID_ecdsa_with_SHA384:       return COSEAlgorithmIdentifierType::AlgES384;
            case NID_ecdsa_with_SHA512:       return COSEAlgorithmIdentifierType::AlgES512;
            case NID_pkcs1:                   ;
            case NID_rsa:                     return COSEAlgorithmIdentifierType::AlgRS1;
            case NID_sha256WithRSAEncryption: return COSEAlgorithmIdentifierType::AlgRS256;
            case NID_sha384WithRSAEncryption: return COSEAlgorithmIdentifierType::AlgRS384;
            case NID_sha512WithRSAEncryption: return COSEAlgorithmIdentifierType::AlgRS512;
            //case NID_ecdsa_with_SHA256:     ;
            case NID_secp256k1:               return COSEAlgorithmIdentifierType::AlgES256K;
            default:                          return std::nullopt;
        }
    }

    // COSEKeyType is The Key type derived from the IANA COSE AuthData.
    enum class COSEKeyType : int {

        // KeyTypeReserved is a reserved value.
        KeyTypeReserved,
        // OctetKey is an Octet Key.
        OctetKey,
        // EllipticKey is an Elliptic Curve Public Key.
        EllipticKey,
        // RSAKey is an RSA Public Key.
        RSAKey,
        // Symmetric Keys.
        Symmetric,
        // HSSLMS is the public key for HSS/LMS hash-based digital signature.
        HSSLMS
    };

    inline constexpr bool operator <(const enum COSEKeyType selfValue, const enum COSEKeyType inValue) noexcept {

        return static_cast<int>(selfValue) < static_cast<int>(inValue);
    }

    inline constexpr bool operator >(const enum COSEKeyType selfValue, const enum COSEKeyType inValue) noexcept {

        return static_cast<int>(selfValue) > static_cast<int>(inValue);
    }

    inline void from_json(const json& j, COSEKeyType& coseKey) {

        auto value = j.get<int>();
        coseKey = static_cast<COSEKeyType>(value);
    }

    inline void to_json(json& j, const COSEKeyType& coseKey) {

        j = json{
            static_cast<int>(coseKey)
        };
    }

    // COSEEllipticCurveType is an enumeration that represents the COSE Elliptic Curves.
    //
    // Specification: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    enum class COSEEllipticCurveType : int {

        // EllipticCurveReserved is the COSE EC Reserved value.
        EllipticCurveReserved,
        // P256 represents NIST P-256 also known as secp256r1.
        P256,
        // P384 represents NIST P-384 also known as secp384r1.
        P384,
        // P521 represents NIST P-521 also known as secp521r1.
        P521,
        // X25519 for use w/ ECDH only.
        X25519,
        // X448 for use w/ ECDH only.
        X448,
        // Ed25519 for use w/ EdDSA only.
        Ed25519,
        // Ed448 for use w/ EdDSA only.
        Ed448,
        // Secp256k1 is the SECG secp256k1 curve.
        Secp256k1
    };

    inline constexpr bool operator <(const enum COSEEllipticCurveType selfValue, const enum COSEEllipticCurveType inValue) noexcept {

        return static_cast<int>(selfValue) < static_cast<int>(inValue);
    }

    inline constexpr bool operator >(const enum COSEEllipticCurveType selfValue, const enum COSEEllipticCurveType inValue) noexcept {

        return static_cast<int>(selfValue) > static_cast<int>(inValue);
    }

    inline void from_json(const json& j, COSEEllipticCurveType& coseEllipticCurve) {

        auto value = j.get<int>();
        coseEllipticCurve = static_cast<COSEEllipticCurveType>(value);
    }

    inline void to_json(json& j, const COSEEllipticCurveType& coseEllipticCurve) {

        j = json{
            static_cast<int>(coseEllipticCurve)
        };
    }

    inline std::optional<COSEEllipticCurveType> COSEEllipticCurveTypeFromNID(int nid) noexcept {

        switch (nid) {

            //case NID_secp256r1: return COSEEllipticCurveType::P256;
            case NID_secp256k1:   return COSEEllipticCurveType::P256;
            case NID_secp384r1:   return COSEEllipticCurveType::P384;
            case NID_secp521r1:   return COSEEllipticCurveType::P521;
            case NID_X25519:      return COSEEllipticCurveType::X25519;
            case NID_X448:        return COSEEllipticCurveType::X448;
            case NID_ED25519:     return COSEEllipticCurveType::Ed25519;
            case NID_ED448:       return COSEEllipticCurveType::Ed448;
            //case NID_secp256k1: return COSEEllipticCurveType::Secp256k1;
            default:              return std::nullopt;
        }
    }

    // SignatureAlgorithmType represents algorithm enumerations used for COSE signatures.
    enum class SignatureAlgorithmType : int {

        UnknownSignatureAlgorithm,
        MD2WithRSA,
        MD5WithRSA,
        SHA1WithRSA,
        SHA256WithRSA,
        SHA384WithRSA,
        SHA512WithRSA,
        DSAWithSHA1,
        DSAWithSHA256,
        ECDSAWithSHA1,
        ECDSAWithSHA256,
        ECDSAWithSHA384,
        ECDSAWithSHA512,
        SHA256WithRSAPSS,
        SHA384WithRSAPSS,
        SHA512WithRSAPSS
    };

    inline void from_json(const json& j, SignatureAlgorithmType& signatureAlgorithm) {

        auto value = j.get<int>();
        signatureAlgorithm = static_cast<SignatureAlgorithmType>(value);
    }

    inline void to_json(json& j, const SignatureAlgorithmType& signatureAlgorithm) {

        j = json{
            static_cast<int>(signatureAlgorithm)
        };
    }

    inline std::string SignatureAlgorithmTypeToString(const SignatureAlgorithmType signatureAlgorithm) noexcept {

        switch (signatureAlgorithm) {

            case SignatureAlgorithmType::UnknownSignatureAlgorithm: return "SHA512"s;
            case SignatureAlgorithmType::MD2WithRSA:                return "MD2"s;
            case SignatureAlgorithmType::MD5WithRSA:                return "MD5"s;    // EVP_md5();
            case SignatureAlgorithmType::SHA1WithRSA:               return "SHA1"s;   // EVP_sha1();
            case SignatureAlgorithmType::SHA256WithRSA:             return "SHA256"s; // EVP_sha256()
            case SignatureAlgorithmType::SHA384WithRSA:             return "SHA384"s; // EVP_sha384();
            case SignatureAlgorithmType::SHA512WithRSA:             return "SHA512"s; // EVP_sha512();
            case SignatureAlgorithmType::DSAWithSHA1:               return "SHA1"s;
            case SignatureAlgorithmType::DSAWithSHA256:             return "SHA256"s;
            case SignatureAlgorithmType::ECDSAWithSHA1:             return "SHA1"s;
            case SignatureAlgorithmType::ECDSAWithSHA256:           return "SHA256"s;
            case SignatureAlgorithmType::ECDSAWithSHA384:           return "SHA384"s;
            case SignatureAlgorithmType::ECDSAWithSHA512:           return "SHA512"s;
            case SignatureAlgorithmType::SHA256WithRSAPSS:          return "SHA256"s;
            case SignatureAlgorithmType::SHA384WithRSAPSS:          return "SHA384"s;
            case SignatureAlgorithmType::SHA512WithRSAPSS:          return "SHA512"s;
            default:                                                return ""s;
        }
    }

    // Errors

    struct ErrUnsupportedKey : public ErrorType {

        ErrUnsupportedKey() noexcept :
            ErrorType(
                "invalid_key_type"s,
                "Unsupported Public Key Type"s) {
        }
    };
    
    struct ErrUnsupportedAlgorithm : public ErrorType {

        ErrUnsupportedAlgorithm() noexcept :
            ErrorType(
                "unsupported_key_algorithm"s,
                "Unsupported public key algorithm"s) {
        }
    };
    
    struct ErrSigNotProvidedOrInvalid : public ErrorType {

        ErrSigNotProvidedOrInvalid() noexcept :
            ErrorType(
                "signature_not_provided_or_invalid"s,
                "Signature invalid or not provided"s) {
        }
    };

    // Structs

    using HasherHandlerType = std::vector<uint8_t> (*)(const std::vector<uint8_t>& data);
    inline constexpr HasherHandlerType DEFAULT_HASHER = Util::Crypto::SHA256;

    inline const struct {
        SignatureAlgorithmType algo;
        COSEAlgorithmIdentifierType coseAlg;
        std::string name;
        HasherHandlerType hasher;
    } SIGNATURE_ALGORITHM_DETAILS[] {
        { SignatureAlgorithmType::SHA1WithRSA,                 COSEAlgorithmIdentifierType::AlgRS1,      "SHA1-RSA"s,   Util::Crypto::SHA1 },
        { SignatureAlgorithmType::SHA256WithRSA,             COSEAlgorithmIdentifierType::AlgRS256,    "SHA256-RSA"s, Util::Crypto::SHA256 },
        { SignatureAlgorithmType::SHA384WithRSA,             COSEAlgorithmIdentifierType::AlgRS384,    "SHA384-RSA"s, Util::Crypto::SHA384 },
        { SignatureAlgorithmType::SHA512WithRSA,             COSEAlgorithmIdentifierType::AlgRS512,    "SHA512-RSA"s, Util::Crypto::SHA512 },
        { SignatureAlgorithmType::SHA256WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS256, "SHA256-RSAPSS"s, Util::Crypto::SHA256 },
        { SignatureAlgorithmType::SHA384WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS384, "SHA384-RSAPSS"s, Util::Crypto::SHA384 },
        { SignatureAlgorithmType::SHA512WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS512, "SHA512-RSAPSS"s, Util::Crypto::SHA512 },
        { SignatureAlgorithmType::ECDSAWithSHA256,           COSEAlgorithmIdentifierType::AlgES256,  "ECDSA-SHA256"s, Util::Crypto::SHA256 },
        { SignatureAlgorithmType::ECDSAWithSHA384,           COSEAlgorithmIdentifierType::AlgES384,  "ECDSA-SHA384"s, Util::Crypto::SHA384 },
        { SignatureAlgorithmType::ECDSAWithSHA512,           COSEAlgorithmIdentifierType::AlgES512,  "ECDSA-SHA512"s, Util::Crypto::SHA512 },
        { SignatureAlgorithmType::UnknownSignatureAlgorithm, COSEAlgorithmIdentifierType::AlgEdDSA,         "EdDSA"s, Util::Crypto::SHA512 }
    };

    // SigAlgFromCOSEAlg return which signature algorithm is being used from the COSE Key.
    inline SignatureAlgorithmType SigAlgFromCOSEAlg(COSEAlgorithmIdentifierType coseAlg) noexcept {

        const auto sz = sizeof(SIGNATURE_ALGORITHM_DETAILS) / sizeof(SIGNATURE_ALGORITHM_DETAILS[0]);

        auto it = std::find_if(SIGNATURE_ALGORITHM_DETAILS, 
                               SIGNATURE_ALGORITHM_DETAILS + sz, [&coseAlg](const auto& details) { return details.coseAlg == coseAlg; });

        return (it != SIGNATURE_ALGORITHM_DETAILS + sz) ? it->algo : SignatureAlgorithmType::UnknownSignatureAlgorithm;
    }

    // HasherFromCOSEAlg returns the Hashing interface to be used for a given COSE Algorithm.
    inline HasherHandlerType HasherFromCOSEAlg(COSEAlgorithmIdentifierType coseAlg) noexcept {

        const auto sz = sizeof(SIGNATURE_ALGORITHM_DETAILS) / sizeof(SIGNATURE_ALGORITHM_DETAILS[0]);

        auto it = std::find_if(SIGNATURE_ALGORITHM_DETAILS, 
                               SIGNATURE_ALGORITHM_DETAILS + sz, [&coseAlg](const auto& details) { return details.coseAlg == coseAlg; });

        return (it != SIGNATURE_ALGORITHM_DETAILS + sz) ? it->hasher : DEFAULT_HASHER;  // default to SHA256?  Why not.
    }

    // PublicKeyDataType The public key portion of a Relying Party-specific credential key pair, generated
    // by an authenticator and returned to a Relying Party at registration time. We unpack this object
    // using fxamacker's cbor library ("github.com/fxamacker/cbor/v2") which is why there are cbor tags
    // included. The tag field values correspond to the IANA COSE keys that give their respective
    // values.
    //
    // Specification: §6.4.1.1. Examples of credentialPublicKey Values Encoded in COSE_Key Format (https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples)
    struct PublicKeyDataType {

        PublicKeyDataType() noexcept = default;

        PublicKeyDataType(int64_t keyType, int64_t algorithm) noexcept :
            KeyType(keyType), 
            Algorithm(algorithm) {
        }

        PublicKeyDataType(const json& j) :
            _struct(j["public_key"].get<bool>()),
            KeyType(j["kty"].get<int64_t>()),
            Algorithm(j["alg"].get<int64_t>()) {
        }

        PublicKeyDataType(const PublicKeyDataType& publicKeyData) noexcept = default;
        PublicKeyDataType(PublicKeyDataType&& publicKeyData) noexcept = default;
        virtual ~PublicKeyDataType() noexcept = default;

        PublicKeyDataType& operator =(const PublicKeyDataType& other) noexcept = default;
        PublicKeyDataType& operator =(PublicKeyDataType&& other) noexcept = default;

        virtual expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept {

            return false;
        }

        // Decode the results to int by default.
        bool _struct;      // cbor:",keyasint"
        // The type of key created. Should be OKP, EC2, or RSA.
        int64_t KeyType;   // cbor:"1,keyasint"
        // A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
        int64_t Algorithm; // cbor:"3,keyasint"
    };

    inline void to_json(json& j, const PublicKeyDataType& publicKeyData) {

        j = json{
            { "public_key", publicKeyData._struct },
            { "kty",        publicKeyData.KeyType },
            { "alg",      publicKeyData.Algorithm }
        };
    }

    inline void from_json(const json& j, PublicKeyDataType& publicKeyData) {

        j.at("public_key").get_to(publicKeyData._struct);
        j.at("kty").get_to(publicKeyData.KeyType);
        j.at("alg").get_to(publicKeyData.Algorithm);
    }

    struct EC2PublicKeyDataType : public PublicKeyDataType {

        EC2PublicKeyDataType() noexcept = default;

        EC2PublicKeyDataType(const PublicKeyDataType& publicKeyData,
            const std::optional<int64_t>& curve, 
            const std::optional<std::vector<uint8_t>>& xCoord,
            const std::optional<std::vector<uint8_t>>& yCoord) noexcept :
            PublicKeyDataType(publicKeyData),
            Curve(curve),
            XCoord(xCoord),
            YCoord(yCoord) {
        }

        EC2PublicKeyDataType(const PublicKeyDataType& pk) noexcept :
            PublicKeyDataType(pk) {
        }

        EC2PublicKeyDataType(const json& j) :
            PublicKeyDataType(j) {
            
            if (j.find("crv") != j.end()) {
                Curve.emplace(j["crv"].get<int64_t>());
            }

            if (j.find("x") != j.end()) {
                XCoord.emplace(j["x"].get<std::vector<uint8_t>>());
            }

            if (j.find("y") != j.end()) {
                YCoord.emplace(j["y"].get<std::vector<uint8_t>>());
            }
        }

        EC2PublicKeyDataType(const EC2PublicKeyDataType& ec2PublicKeyData) noexcept = default;
        EC2PublicKeyDataType(EC2PublicKeyDataType&& ec2PublicKeyData) noexcept = default;
        ~EC2PublicKeyDataType() noexcept override = default;

        EC2PublicKeyDataType& operator =(const EC2PublicKeyDataType& other) noexcept = default;
        EC2PublicKeyDataType& operator =(EC2PublicKeyDataType&& other) noexcept = default;

        inline bool operator ==(const EC2PublicKeyDataType& other) const noexcept {

            return Curve == other.Curve && XCoord == other.XCoord && YCoord == other.YCoord;
        }

        inline bool operator !=(const EC2PublicKeyDataType& other) const noexcept {

            return Curve != other.Curve || XCoord != other.XCoord || YCoord != other.YCoord;
        }

        // Verify Elliptic Curve Public Key Signature.
        expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept override {

            if (!XCoord) {

                return unexpected("XCoord param missing"s);
            }

            if (!YCoord) {

                return unexpected("YCoord param missing"s);
            }
            auto coseAlg = static_cast<COSEAlgorithmIdentifierType>(Algorithm);
            auto sigAlg = SigAlgFromCOSEAlg(coseAlg);
            auto algorithmName = SignatureAlgorithmTypeToString(sigAlg);

            if (algorithmName.empty()) {

                return unexpected("Unknown unsupported algorithm"s);
            }

            char CURVE_P521[] = "P-521";
            char CURVE_P384[] = "P-384";
            char CURVE_P256[] = "P-256";
            char* curve = nullptr;

            switch (Algorithm) {

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES512): // IANA COSE code for ECDSA w/ SHA-512.
                    curve = CURVE_P521; //NID_secp521r1;
                    break;

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES384): // IANA COSE code for ECDSA w/ SHA-384.
                    curve = CURVE_P384; //NID_secp384r1;
                    break;

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES256): // IANA COSE code for ECDSA w/ SHA-256.
                    curve = CURVE_P256; //NID_secp256k1;
                    break;

                default:
                    return unexpected(ErrUnsupportedAlgorithm());
            }
            //auto pKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            auto pKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);

            if (pKeyCtx == nullptr) {

                return unexpected("Could not create an EC key generation context"s);
            }

            if (EVP_PKEY_fromdata_init(pKeyCtx) != 1) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not init EC key generation"s);
            }
            std::vector<uint8_t> pubKeyData(1 + XCoord.value().size() + YCoord.value().size());
            pubKeyData[0] = static_cast<uint8_t>(0x04);
            std::memcpy(pubKeyData.data() + 1, XCoord.value().data(), XCoord.value().size());
            std::memcpy(pubKeyData.data() + XCoord.value().size() + 1, YCoord.value().data(), YCoord.value().size());
            OSSL_PARAM params[]{
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve, 0),
                /*OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X,
                              const_cast<uint8_t*>(XCoord.value().data()),
                              XCoord.value().size()),
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y,
                              const_cast<uint8_t*>(XCoord.value().data()),
                              YCoord.value().size()),*/
                OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubKeyData.data(), pubKeyData.size()),
                OSSL_PARAM_END
            };
            /*auto bld = OSSL_PARAM_BLD_new();

            if (bld == nullptr) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not start creating EC key params"s);
            }
            if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0) != 1 ||
                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubKeyData.data(), pubKeyData.size()) != 1) {

                OSSL_PARAM_BLD_free(bld);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not start creating EC key params"s);
            }
            auto params = OSSL_PARAM_BLD_to_param(bld);

            if (params == nullptr) {

                OSSL_PARAM_BLD_free(bld);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not create EC key params"s);
            }*/
            EVP_PKEY* pKey = nullptr;

            if (EVP_PKEY_fromdata(pKeyCtx, &pKey, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
                pKey == nullptr) {

                //OSSL_PARAM_free(params);
                //OSSL_PARAM_BLD_free(bld);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not generate EC key"s);
            }
            auto mdCtx = EVP_MD_CTX_new();

            if (mdCtx == nullptr) {

                EVP_PKEY_free(pKey);
                //OSSL_PARAM_free(params);
                //OSSL_PARAM_BLD_free(bld);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not create MD context"s);
            }
            auto result = EVP_DigestVerifyInit_ex(mdCtx, nullptr, algorithmName.c_str(), nullptr, nullptr, pKey, nullptr);

            if (result != 1) {

                EVP_MD_CTX_free(mdCtx);
                EVP_PKEY_free(pKey);
                //OSSL_PARAM_free(params);
                //OSSL_PARAM_BLD_free(bld);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, sig.data(), sig.size(), data.data(), data.size());
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(pKey);
            //OSSL_PARAM_free(params);
            //OSSL_PARAM_BLD_free(bld);
            EVP_PKEY_CTX_free(pKeyCtx);

            if (result == 0 || result == 1) {

                return result == 1;
            } else {

                return unexpected("Could not check signature"s);
            }
        }

        // If the key type is EC2, the curve on which we derive the signature from.
        std::optional<int64_t> Curve; // cbor:"-1,keyasint,omitempty"
        // A byte string 32 bytes in length that holds the x coordinate of the key.
        std::optional<std::vector<uint8_t>> XCoord; // cbor:"-2,keyasint,omitempty"
        // A byte string 32 bytes in length that holds the y coordinate of the key.
        std::optional<std::vector<uint8_t>> YCoord; // cbor:"-3,keyasint,omitempty"
    };

    inline void to_json(json& j, const EC2PublicKeyDataType& ec2PublicKeyData) {

        json _j;
        to_json(_j, static_cast<const PublicKeyDataType&>(ec2PublicKeyData));

        if (ec2PublicKeyData.Curve) {
            _j["crv"] = ec2PublicKeyData.Curve.value();
        }

        if (ec2PublicKeyData.XCoord) {
            _j["x"] = ec2PublicKeyData.XCoord.value();
        }

        if (ec2PublicKeyData.YCoord) {
            _j["y"] = ec2PublicKeyData.YCoord.value();
        }

        j = _j;
    }

    inline void from_json(const json& j, EC2PublicKeyDataType& ec2PublicKeyData) {

        from_json(j, static_cast<PublicKeyDataType&>(ec2PublicKeyData));

        if (j.find("crv") != j.end()) {
            ec2PublicKeyData.Curve.emplace(j["crv"].get<int64_t>());
        }

        if (j.find("x") != j.end()) {
            ec2PublicKeyData.XCoord.emplace(j["x"].get<std::vector<uint8_t>>());
        }

        if (j.find("y") != j.end()) {
            ec2PublicKeyData.YCoord.emplace(j["y"].get<std::vector<uint8_t>>());
        }
    }

    struct RSAPublicKeyDataType : public PublicKeyDataType {

        RSAPublicKeyDataType() noexcept = default;

        RSAPublicKeyDataType(const PublicKeyDataType& pk) noexcept :
            PublicKeyDataType(pk) {
        }

        RSAPublicKeyDataType(const json& j) :
            PublicKeyDataType(j) {

            if (j.find("n") != j.end()) {
                Modulus.emplace(j["n"].get<std::vector<uint8_t>>());
            }

            if (j.find("e") != j.end()) {
                Exponent.emplace(j["e"].get<std::vector<uint8_t>>());
            }
        }

        RSAPublicKeyDataType(const RSAPublicKeyDataType& rsaPublicKeyData) noexcept = default;
        RSAPublicKeyDataType(RSAPublicKeyDataType&& rsaPublicKeyData) noexcept = default;
        ~RSAPublicKeyDataType() noexcept override = default;

        RSAPublicKeyDataType& operator =(const RSAPublicKeyDataType& other) noexcept = default;
        RSAPublicKeyDataType& operator =(RSAPublicKeyDataType&& other) noexcept = default;

        // Verify RSA Public Key Signature.
        expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept override {

            if (!Modulus) {

                return unexpected("Modulus param missing"s);
            }

            if (!Exponent) {

                return unexpected("Exponent param missing"s);
            }

            if (Exponent.value().size() < 3) {

                return unexpected("Exponent param too small"s);
            }
            auto coseAlg = static_cast<COSEAlgorithmIdentifierType>(Algorithm);
            auto sigAlg = SigAlgFromCOSEAlg(coseAlg);
            auto algorithmName = SignatureAlgorithmTypeToString(sigAlg);

            if (algorithmName.empty()) {

                return unexpected("Unknown unsupported algorithm"s);
            }
            EVP_PKEY_CTX* pKeyCtx = nullptr;

            switch (Algorithm) {

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgPS256):
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgPS384):
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgPS512):
                    //pKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr);
                    pKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "RSASSA-PSS", nullptr);
                    break;
                
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgRS1):
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgRS256):
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgRS384):
                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgRS512):
                    //pKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA2, nullptr);
                    pKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
                    break;

                default:
                    return unexpected(ErrUnsupportedAlgorithm());
            }

            if (pKeyCtx == nullptr) {

                return unexpected("Could not create an RSA key generation context"s);
            }

            if (EVP_PKEY_fromdata_init(pKeyCtx) != 1) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not init RSA key generation"s);
            }
            //std::vector<uint8_t> pubKeyData(Modulus.value() + 4);
            //pubKeyData[0] = static_cast<uint8_t>(0x30);
            // ... pubKeyData[...] = ....
            //std::memcpy(pubKeyData.data() + 1, Modulus.value().data(), Modulus.value().size());
            //pubKeyData[pubKeyData.data() + Modulus.value().size() + 1] = Exponent.value()[0];
            //pubKeyData[pubKeyData.data() + Modulus.value().size() + 2] = Exponent.value()[1];
            //pubKeyData[pubKeyData.data() + Modulus.value().size() + 3] = Exponent.value()[2];
            auto exponent = static_cast<int32_t>(static_cast<uint32_t>(Exponent.value()[2]) |
                                                 (static_cast<uint32_t>(Exponent.value()[1]) << 8) |
                                                 (static_cast<uint32_t>(Exponent.value()[0]) << 16));
            OSSL_PARAM params[]{
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N,
                              const_cast<uint8_t*>(Modulus.value().data()), 
                              Modulus.value().size()),
                OSSL_PARAM_int32(OSSL_PKEY_PARAM_RSA_EXPONENT,
                                 &exponent),
                //OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubKeyData.data(), pubKeyData.size()),
                OSSL_PARAM_END
            };
            EVP_PKEY* pKey = nullptr;

            if (EVP_PKEY_fromdata(pKeyCtx, &pKey, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
                pKey == nullptr) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not generate RSA key"s);
            }
            auto mdCtx = EVP_MD_CTX_new();

            if (mdCtx == nullptr) {

                EVP_PKEY_free(pKey);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not create MD context"s);
            }
            auto result = EVP_DigestVerifyInit_ex(mdCtx, nullptr, algorithmName.c_str(), nullptr, nullptr, pKey, nullptr);

            if (result != 1) {

                EVP_MD_CTX_free(mdCtx);
                EVP_PKEY_free(pKey);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, sig.data(), sig.size(), data.data(), data.size()); // Verify PSS or PKCS1v15
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(pKey);
            EVP_PKEY_CTX_free(pKeyCtx);

            if (result == 0 || result == 1) {

                return result == 1;
            } else {

                return unexpected("Could not check signature"s);
            }
        }

        // Represents the modulus parameter for the RSA algorithm.
        std::optional<std::vector<uint8_t>> Modulus; // cbor:"-1,keyasint,omitempty"
        // Represents the exponent parameter for the RSA algorithm.
        std::optional<std::vector<uint8_t>> Exponent; // cbor:"-2,keyasint,omitempty"
    };

    inline void to_json(json& j, const RSAPublicKeyDataType& rsaPublicKeyData) {

        json _j;
        to_json(_j, static_cast<const PublicKeyDataType&>(rsaPublicKeyData));

        if (rsaPublicKeyData.Modulus) {
            _j["n"] = rsaPublicKeyData.Modulus.value();
        }

        if (rsaPublicKeyData.Exponent) {
            _j["e"] = rsaPublicKeyData.Exponent.value();
        }

        j = _j;
    }

    inline void from_json(const json& j, RSAPublicKeyDataType& rsaPublicKeyData) {

        from_json(j, static_cast<PublicKeyDataType&>(rsaPublicKeyData));

        if (j.find("n") != j.end()) {
            rsaPublicKeyData.Modulus.emplace(j["n"].get<std::vector<uint8_t>>());
        }

        if (j.find("e") != j.end()) {
            rsaPublicKeyData.Exponent.emplace(j["e"].get<std::vector<uint8_t>>());
        }
    }

    struct OKPPublicKeyDataType : public PublicKeyDataType {

        OKPPublicKeyDataType() noexcept = default;

        OKPPublicKeyDataType(const PublicKeyDataType& pk) noexcept :
            PublicKeyDataType(pk) {
        }

        OKPPublicKeyDataType(const json& j) :
            PublicKeyDataType(j) {

            if (j.find("x") != j.end()) {
                XCoord.emplace(j["x"].get<std::vector<uint8_t>>());
            }
        }

        OKPPublicKeyDataType(const OKPPublicKeyDataType& okpPublicKeyData) noexcept = default;
        OKPPublicKeyDataType(OKPPublicKeyDataType&& okpPublicKeyData) noexcept = default;
        ~OKPPublicKeyDataType() noexcept override = default;

        OKPPublicKeyDataType& operator =(const OKPPublicKeyDataType& other) noexcept = default;
        OKPPublicKeyDataType& operator =(OKPPublicKeyDataType&& other) noexcept = default;

        // Verify Octet Key Pair (OKP) Public Key Signature.
        expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept override {

            if (!XCoord) {

                return unexpected("XCoord param missing"s);
            }

            if (Algorithm != static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgEdDSA)) {

                return unexpected("Unknown unsupported algorithm"s);
            }
            auto coseAlg = static_cast<COSEAlgorithmIdentifierType>(Algorithm);
            auto sigAlg = SigAlgFromCOSEAlg(coseAlg);
            auto algorithmName = SignatureAlgorithmTypeToString(sigAlg);

            if (algorithmName.empty()) {

                return unexpected("Unknown unsupported algorithm"s);
            }
            //auto pKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            auto pKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);

            if (pKeyCtx == nullptr) {

                return unexpected("Could not create an Ed25519 key generation context"s);
            }

            if (EVP_PKEY_fromdata_init(pKeyCtx) != 1) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not init Ed25519 key generation"s);
            }

#ifndef OSSL_SIGNATURE_PARAM_INSTANCE
#define OSSL_SIGNATURE_PARAM_INSTANCE "instance"
#endif

#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

            std::vector<uint8_t> pubKeyData(XCoord.value());
            char Ed25519[] = "Ed25519";
            OSSL_PARAM params[]{
                OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, Ed25519, 0),
                OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, pubKeyData.data(), pubKeyData.size()),
                OSSL_PARAM_END
            };
            EVP_PKEY* pKey = nullptr;

            if (EVP_PKEY_fromdata(pKeyCtx, &pKey, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
                pKey == nullptr) {

                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not generate Ed25519 key"s);
            }
            auto mdCtx = EVP_MD_CTX_new();

            if (mdCtx == nullptr) {

                EVP_PKEY_free(pKey);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Could not create MD context"s);
            }
            auto result = EVP_DigestVerifyInit_ex(mdCtx, nullptr, algorithmName.c_str(), nullptr, nullptr, pKey, nullptr);

            if (result != 1) {

                EVP_MD_CTX_free(mdCtx);
                EVP_PKEY_free(pKey);
                EVP_PKEY_CTX_free(pKeyCtx);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, sig.data(), sig.size(), data.data(), data.size());
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(pKey);
            EVP_PKEY_CTX_free(pKeyCtx);

            if (result == 0 || result == 1) {

                return result == 1;
            } else {

                return unexpected("Could not check signature"s);
            }
        }

        int64_t Curve;
        // A byte string that holds the x coordinate of the key.
        std::optional<std::vector<uint8_t>> XCoord; // cbor:"-2,keyasint,omitempty"
    };

    inline void to_json(json& j, const OKPPublicKeyDataType& okpPublicKeyData) {

        json _j;
        to_json(_j, static_cast<const PublicKeyDataType&>(okpPublicKeyData));

        if (okpPublicKeyData.XCoord) {
            _j["x"] = okpPublicKeyData.XCoord.value();
        }

        j = _j;
    }

    inline void from_json(const json& j, OKPPublicKeyDataType& okpPublicKeyData) {

        from_json(j, static_cast<PublicKeyDataType&>(okpPublicKeyData));

        if (j.find("x") != j.end()) {
            okpPublicKeyData.XCoord.emplace(j["x"].get<std::vector<uint8_t>>());
        }
    }

    // Functions

#pragma GCC visibility push(hidden)

    namespace {

        static inline expected<PublicKeyDataType>
        _PublicKeyDataFromCBOR(const cbor_pair* items, size_t size) noexcept {

            if (items == nullptr || size == 0) {

                return unexpected("No CBOR data available to parse a public key"s);
            }

            PublicKeyDataType pk{};
            auto fieldCount = 0;

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_uint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = cbor_get_uint8(item.key);

                    switch (k) {

                        case 1: {

                            pk.KeyType = cbor_isa_uint(item.value) ? cbor_get_uint8(item.value) : 0;
                            ++fieldCount;
                            break;
                        }

                        case 3: {

                            pk.Algorithm = cbor_isa_negint(item.value) ? 
                                                -(cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8 ? cbor_get_uint8(item.value) : cbor_get_uint16(item.value)) - 1
                                                : 0;
                            ++fieldCount;
                            break;
                        }

                        default:
                            break;
                    }
                }
            }

            if (fieldCount < 2) {

                return unexpected("Could not CBOR-decode public key: could not find all public key fields"s);
            }

            return pk;
        }

        static inline expected<OKPPublicKeyDataType>
        _OKPPublicKeyDataFromCBOR(const PublicKeyDataType& pk, const cbor_pair* items, size_t size) noexcept {

            OKPPublicKeyDataType okp{pk};
            auto fieldCount = 0;

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_negint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = -cbor_get_uint8(item.key) - 1;

                    switch (k) {

                        case -1: okp.Curve = cbor_isa_uint(item.value) ? cbor_get_uint64(item.value) : -cbor_get_uint64(item.value) - 1;
                            ++fieldCount;
                            break;

                        case -2: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    okp.XCoord = std::vector<uint8_t>(data, data + dataSize);
                                }
                                ++fieldCount;
                            }
                            break;
                        }

                        default:
                            break;
                    }
                }
            }

            if (fieldCount < 2) {

                return unexpected("Could not CBOR-decode OKP public key: could not find all fields"s);
            }

            return okp;
        }

        static inline expected<EC2PublicKeyDataType>
        _EC2PublicKeyDataFromCBOR(const PublicKeyDataType& pk, const cbor_pair* items, size_t size) noexcept {

            EC2PublicKeyDataType ec2{pk};
            auto fieldCount = 0;

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_negint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = -cbor_get_uint8(item.key) - 1;

                    switch (k) {

                        case -1: ec2.Curve = cbor_isa_uint(item.value) ? cbor_get_uint64(item.value) : -cbor_get_uint64(item.value) - 1;
                            ++fieldCount;
                            break;

                        case -2: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    ec2.XCoord = std::vector<uint8_t>(data, data + dataSize);
                                }
                                ++fieldCount;
                            }
                            break;
                        }
                        
                        case -3: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    ec2.YCoord = std::vector<uint8_t>(data, data + dataSize);
                                }
                                ++fieldCount;
                            }
                            break;
                        }

                        default:
                            break;
                    }
                }
            }

            if (fieldCount < 3) {

                return unexpected("Could not CBOR-decode EC2 public key: could not find all fields"s);
            }

            return ec2;
        }

        static inline expected<RSAPublicKeyDataType>
        _RSAPublicKeyDataFromCBOR(const PublicKeyDataType& pk, const cbor_pair* items, size_t size) noexcept {

            RSAPublicKeyDataType rsa{pk};
            auto fieldCount = 0;

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_negint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = -cbor_get_uint8(item.key) - 1;

                    switch (k) {

                        case -1: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    rsa.Modulus = std::vector<uint8_t>(data, data + dataSize);
                                }
                                ++fieldCount;
                            }
                            break;
                        }

                        case -2: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    rsa.Exponent = std::vector<uint8_t>(data, data + dataSize);
                                }
                                ++fieldCount;
                            }
                            break;
                        }

                        default:
                            break;
                    }
                }
            }

            if (fieldCount < 2) {

                return unexpected("Could not CBOR-decode RSA public key: could not find all fields"s);
            }

            return rsa;
        }
    } // namespace

#pragma GCC visibility pop

    // ParsePublicKey figures out what kind of COSE material was provided and create the data for the new key.
    inline expected<std::any> ParsePublicKey(const std::vector<uint8_t>& keyBytes) noexcept {

        auto unmarshalResult = WebAuthNCBOR::Unmarshal(keyBytes);

        if (!unmarshalResult) {

            return unexpected("Could not CBOR-decode public key"s);
        }
        auto cborItem = unmarshalResult.value();

        if (cbor_isa_map(cborItem) && cbor_map_is_definite(cborItem)) {

            auto size = cbor_map_size(cborItem);
            auto items = cbor_map_handle(cborItem);
            auto pkResult = _PublicKeyDataFromCBOR(items, size);

            if (!pkResult) {

                cbor_decref(&cborItem);
                return unexpected(pkResult.error());
            }
            auto pk = pkResult.value();

            switch (pk.KeyType) {

                case static_cast<int64_t>(COSEKeyType::OctetKey): {

                    auto okpPkResult = _OKPPublicKeyDataFromCBOR(pk, items, size);

                    if (!okpPkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(okpPkResult.error());
                    }
                    auto okp = okpPkResult.value();

                    cbor_decref(&cborItem);
                    return okp;
                }

                case static_cast<int64_t>(COSEKeyType::EllipticKey): {

                    auto ec2PkResult = _EC2PublicKeyDataFromCBOR(pk, items, size);

                    if (!ec2PkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(ec2PkResult.error());
                    }
                    auto ec2 = ec2PkResult.value();

                    cbor_decref(&cborItem);
                    return ec2;
                }

                case static_cast<int64_t>(COSEKeyType::RSAKey): {

                    auto rsaPkResult = _RSAPublicKeyDataFromCBOR(pk, items, size);

                    if (!rsaPkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(rsaPkResult.error());
                    }
                    auto rsa = rsaPkResult.value();

                    cbor_decref(&cborItem);
                    return rsa;
                }

                default: {

                    cbor_decref(&cborItem);
                    return unexpected(std::string(ErrUnsupportedKey()));
                }
            }
        } else {

            cbor_decref(&cborItem);
            return unexpected("Could not CBOR-decode public key: root element is not a map"s);
        }
    }

    // ParseFIDOPublicKey is only used when the appID extension is configured by the assertion response.
    inline expected<EC2PublicKeyDataType> ParseFIDOPublicKey(const std::vector<uint8_t>& keyBytes) noexcept {

        auto unmarshalResult = WebAuthNCBOR::Unmarshal(keyBytes);

        if (!unmarshalResult) {

            return unexpected("Could not CBOR-decode public key"s);
        }
        auto cborItem = unmarshalResult.value();
        EC2PublicKeyDataType ec2{};
        ec2.Algorithm = static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES256);

        if (cbor_isa_map(cborItem) && cbor_map_is_definite(cborItem)) {

            auto size = cbor_map_size(cborItem);
            auto items = cbor_map_handle(cborItem);

            if (items == nullptr || size == 0) {

                cbor_decref(&cborItem);
                return unexpected("No CBOR data available to parse a P256 curve key"s);
            }

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_negint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = -cbor_get_uint8(item.key) - 1;

                    switch (k) {

                        case -1: ec2.Curve = cbor_isa_uint(item.value) ? cbor_get_uint64(item.value) : -cbor_get_uint64(item.value) - 1;
                            break;

                        case -2: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    ec2.XCoord = std::vector<uint8_t>(data, data + dataSize);
                                }
                            }
                            break;
                        }
                        
                        case -3: {

                            if (cbor_isa_bytestring(item.value) && cbor_bytestring_is_definite(item.value)) {

                                auto dataSize = cbor_bytestring_length(item.value);

                                if (dataSize > 0) {
                                    
                                    auto data = cbor_bytestring_handle(item.value);
                                    ec2.YCoord = std::vector<uint8_t>(data, data + dataSize);
                                }
                            }
                            break;
                        }

                        default:
                            break;
                    }
                }
            }
        }
        cbor_decref(&cborItem);

        if (!ec2.XCoord || !ec2.YCoord) { // || !ec2.Curve || !ec2.Curve.value() != static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES256)

            return unexpected("Missing value(s) in elliptic unmarshal"s);
        }

        return ec2;
    }

    /*inline expected<std::vector<uint8_t>> MarshalEd25519PublicKey(const ed25519.PublicKey& pub) {
        
        return x509.MarshalPKIXPublicKey(pub);
    }

    {
        const asn1.ObjectIdentifier oidSignatureEd25519{1, 3, 101, 112};

        struct PkixPublicKeyType {
            pkix.AlgorithmIdentifier Algo;
            asn1.BitString BitString;
        };

        // MarshalEd25519PublicKey is a backport of the functionality introduced in
        // Go v1.13.
        // Ref: https://golang.org/doc/go1.13#crypto/ed25519
        // Ref: https://golang.org/doc/go1.13#crypto/x509
        inline expected<std::vector<uint8_t>> MarshalEd25519PublicKey(const ed25519.PublicKey& pub) {
            
            publicKeyBytes := pub
            var publicKeyAlgorithm pkix.AlgorithmIdentifier
            publicKeyAlgorithm.Algorithm = oidSignatureEd25519

            pkix := pkixPublicKey{
                Algo: publicKeyAlgorithm,
                BitString: asn1.BitString{
                    Bytes:     publicKeyBytes,
                    BitLength: 8 * len(publicKeyBytes),
                },
            }

            ret, _ := asn1.Marshal(pkix)
            return ret, nil
        }
    }*/

    inline ValueType<PublicKeyDataType> KeyCast(const std::any& key, bool& success) noexcept {

        static ValueType<PublicKeyDataType> vpk{PublicKeyDataType{}};
        success = true;

        try {
            
            return ValueType<PublicKeyDataType>{std::any_cast<const OKPPublicKeyDataType&>(key)};
        } catch(const std::bad_any_cast&) {

            try {
                
                return ValueType<PublicKeyDataType>{std::any_cast<const EC2PublicKeyDataType&>(key)};
            } catch(const std::bad_any_cast&) {

                try {
                    
                    return ValueType<PublicKeyDataType>{std::any_cast<const RSAPublicKeyDataType&>(key)};
                } catch(const std::bad_any_cast&) {

                    success = false;
                }
            }
        }

        return vpk;
    }

    inline expected<bool>
    VerifySignature(const std::any& key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) noexcept {

        auto success = false;
        auto vpk = KeyCast(key, success);

        if (success) {

            return vpk.Value.Verify(data, sig);
        }

        return unexpected(ErrUnsupportedKey());
    }
} // namespace WebAuthN::Protocol::WebAuthNCOSE

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP */
