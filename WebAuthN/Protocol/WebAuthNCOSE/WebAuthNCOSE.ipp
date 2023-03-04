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
#include <openssl/ecdsa.h>

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

            case SignatureAlgorithmType::UnknownSignatureAlgorithm: return "unknownSignatureAlgorithm"s;
            case SignatureAlgorithmType::MD2WithRSA:                return "md2WithRSA"s;
            case SignatureAlgorithmType::MD5WithRSA:                return "md5WithRSA"s;
            case SignatureAlgorithmType::SHA1WithRSA:               return "sha1WithRSA"s;
            case SignatureAlgorithmType::SHA256WithRSA:             return "sha256WithRSA"s;
            case SignatureAlgorithmType::SHA384WithRSA:             return "sha384WithRSA"s;
            case SignatureAlgorithmType::SHA512WithRSA:             return "sha512WithRSA"s;
            case SignatureAlgorithmType::DSAWithSHA1:               return "dsaWithSHA1"s;
            case SignatureAlgorithmType::DSAWithSHA256:             return "dsaWithSHA256"s;
            case SignatureAlgorithmType::ECDSAWithSHA1:             return "ecdsaWithSHA1"s;
            case SignatureAlgorithmType::ECDSAWithSHA256:           return "ecdsaWithSHA256"s;
            case SignatureAlgorithmType::ECDSAWithSHA384:           return "ecdsaWithSHA384"s;
            case SignatureAlgorithmType::ECDSAWithSHA512:           return "ecdsaWithSHA512"s;
            case SignatureAlgorithmType::SHA256WithRSAPSS:          return "sha256WithRSAPSS"s;
            case SignatureAlgorithmType::SHA384WithRSAPSS:          return "sha384WithRSAPSS"s;
            case SignatureAlgorithmType::SHA512WithRSAPSS:          return "sha512WithRSAPSS"s;
            default: return ""s;
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

    using HasherHandlerType = std::vector<uint8_t> (*)(const std::string& str);

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

        return (it != SIGNATURE_ALGORITHM_DETAILS + sz) ? it->hasher : Util::Crypto::SHA256;  // default to SHA256?  Why not.
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

        // Verify Elliptic Curve Public Key Signature.
        expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept override {

            int curve{};

            switch (Algorithm) {

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES512): // IANA COSE code for ECDSA w/ SHA-512.
                    curve = NID_secp521r1;
                    break;

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES384): // IANA COSE code for ECDSA w/ SHA-384.
                    curve = NID_secp384r1;
                    break;

                case static_cast<int64_t>(COSEAlgorithmIdentifierType::AlgES256): // IANA COSE code for ECDSA w/ SHA-256.
                    curve = NID_secp256k1;
                    break;

                default:
                    return unexpected(ErrUnsupportedAlgorithm());
            }
            auto ek = EC_KEY_new_by_curve_name(curve);

            if (ek == nullptr) {

                return unexpected("Could not create an EC key"s);
            }
            const auto x = BN_bin2bn(XCoord.value().data(), XCoord.value().size(), nullptr);
            const auto y = BN_bin2bn(YCoord.value().data(), YCoord.value().size(), nullptr);
            EC_KEY_set_public_key_affine_coordinates(ek, x, y);

            auto f = HasherFromCOSEAlg(static_cast<COSEAlgorithmIdentifierType>(Algorithm));
            auto hashData = f(std::string(reinterpret_cast<const char*>(data.data()), data.size()));

            ECDSA_SIG* ecdsaSig = nullptr;
            const uint8_t* pSigData = sig.data();
            d2i_ECDSA_SIG(&ecdsaSig, &pSigData, sig.size());

            if (ecdsaSig == nullptr) {

                EC_KEY_free(ek);
                return unexpected(ErrSigNotProvidedOrInvalid());
            }

            //auto verificationResult = ecdsa.Verify(pubkey, h.Sum(nil), e.R, e.S);

            auto mdCtx = EVP_MD_CTX_new();

            if (mdCtx == nullptr) {

                EC_KEY_free(ek);
                ECDSA_SIG_free(ecdsaSig);
                return unexpected("Could not create MD context"s);
            }
            auto pkey = EVP_PKEY_new();

            if (pkey == nullptr) {

                EVP_MD_CTX_free(mdCtx);
                EC_KEY_free(ek);
                ECDSA_SIG_free(ecdsaSig);
                return unexpected("Could not create a public key"s);
            }

            EVP_PKEY_set1_EC_KEY(pkey, nullptr);
            auto result = EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pkey);

            if (result != 1) {

                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mdCtx);
                EC_KEY_free(ek);
                ECDSA_SIG_free(ecdsaSig);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, sig.data(), sig.size(), hashData.data(), hashData.size());
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(mdCtx);
            EC_KEY_free(ek);
            ECDSA_SIG_free(ecdsaSig);

            if (result == 0 || result == 1) {

                return result == 1;
            } else {

                return unexpected("Could not check signature"s);
            }
        }

        /*inline tpm2.EllipticCurveType TPMCurveID() const noexcept {

            switch COSEEllipticCurve(Curve) {
            case P256:
                return tpm2.CurveNISTP256 // TPM_ECC_NIST_P256.
            case P384:
                return tpm2.CurveNISTP384 // TPM_ECC_NIST_P384.
            case P521:
                return tpm2.CurveNISTP521 // TPM_ECC_NIST_P521.
            default:
                return tpm2.EllipticCurve(0) // TPM_ECC_NONE.
            }
        }*/

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
            return true;
            /*pubkey := &rsa.PublicKey{
                N: big.NewInt(0).SetBytes(Modulus),
                E: int(uint(Exponent[2]) | uint(Exponent[1])<<8 | uint(Exponent[0])<<16),
            }

            f := HasherFromCOSEAlg(COSEAlgorithmIdentifier(Algorithm))
            h := f()
            h.Write(data)

            var hash crypto.Hash

            switch COSEAlgorithmIdentifier(Algorithm) {
            case AlgRS1:
                hash = crypto.SHA1
            case AlgPS256, AlgRS256:
                hash = crypto.SHA256
            case AlgPS384, AlgRS384:
                hash = crypto.SHA384
            case AlgPS512, AlgRS512:
                hash = crypto.SHA512
            default:
                return false, ErrUnsupportedAlgorithm
            }

            switch COSEAlgorithmIdentifier(Algorithm) {
            case AlgPS256, AlgPS384, AlgPS512:
                err := rsa.VerifyPSS(pubkey, hash, h.Sum(nil), sig, nil)

                return err == nil, err
            case AlgRS1, AlgRS256, AlgRS384, AlgRS512:
                err := rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), sig)

                return err == nil, err
            default:
                return false, ErrUnsupportedAlgorithm
            }*/
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
            return true;
            /*var key ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)

            std::copy(key, XCoord);

            return ed25519.Verify(key, data, sig), nil */
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

        inline expected<PublicKeyDataType>
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

                        case 1: pk.KeyType = cbor_isa_uint(item.value) ? cbor_get_uint8(item.value) : 0;
                            ++fieldCount;
                            break;

                        case 3: pk.Algorithm = cbor_isa_negint(item.value) ? 
                                                -(cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8 ? cbor_get_uint8(item.value) : cbor_get_uint16(item.value)) - 1
                                                : 0;
                            ++fieldCount;
                            break;

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

        inline expected<OKPPublicKeyDataType>
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

                        case -2:
                        {
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

        inline expected<EC2PublicKeyDataType>
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

                        case -2:
                        {
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

                       case -3:
                        {
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

        inline expected<RSAPublicKeyDataType>
        _RSAPublicKeyDataFromCBOR(const PublicKeyDataType& pk, const cbor_pair* items, size_t size) noexcept {

            RSAPublicKeyDataType rsa{pk};
            auto fieldCount = 0;

            for (decltype(size) i = 0; i < size; ++i) {

                auto item = *(items + i);

                if (cbor_isa_negint(item.key) && 
                    cbor_int_get_width(item.key) == cbor_int_width::CBOR_INT_8) {

                    auto k = -cbor_get_uint8(item.key) - 1;

                    switch (k) {

                        case -1:
                        {
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

                        case -2:
                        {
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

                case static_cast<int64_t>(COSEKeyType::OctetKey):
                {
                    auto okpPkResult = _OKPPublicKeyDataFromCBOR(pk, items, size);

                    if (!okpPkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(okpPkResult.error());
                    }
                    auto okp = okpPkResult.value();

                    cbor_decref(&cborItem);
                    return okp;
                }

                case static_cast<int64_t>(COSEKeyType::EllipticKey):
                {
                    auto ec2PkResult = _EC2PublicKeyDataFromCBOR(pk, items, size);

                    if (!ec2PkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(ec2PkResult.error());
                    }
                    auto ec2 = ec2PkResult.value();

                    cbor_decref(&cborItem);
                    return ec2;
                }

                case static_cast<int64_t>(COSEKeyType::RSAKey):
                {
                    auto rsaPkResult = _RSAPublicKeyDataFromCBOR(pk, items, size);

                    if (!rsaPkResult) {

                        cbor_decref(&cborItem);
                        return unexpected(rsaPkResult.error());
                    }
                    auto rsa = rsaPkResult.value();

                    cbor_decref(&cborItem);
                    return rsa;
                }

                default:
                {
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
        EC2PublicKeyDataType ec2Pk{};
        return ec2Pk;
        /*x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)

        if x == nil || y == nil {
            return data, fmt::Errorf("elliptic unmarshall returned a nil value");
        }

        return EC2PublicKeyData{
            PublicKeyData: PublicKeyData{
                Algorithm: int64(AlgES256),
            },
            XCoord: x.Bytes(),
            YCoord: y.Bytes(),
        }, nil*/
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

    inline std::string DisplayPublicKey(const std::vector<uint8_t>& cpk) {

        return "";
        
        /*parsedKey, err := ParsePublicKey(cpk)
        if err != nil {
            return keyCannotDisplay
        }

        switch k := parsedKey.(type) {
        case RSAPublicKeyData:
            rKey := &rsa.PublicKey{
                N: big.NewInt(0).SetBytes(k.Modulus),
                E: int(uint(k.Exponent[2]) | uint(k.Exponent[1])<<8 | uint(k.Exponent[0])<<16),
            }

            data, err := x509.MarshalPKIXPublicKey(rKey)
            if err != nil {
                return keyCannotDisplay
            }

            pemBytes := pem.EncodeToMemory(&pem.Block{
                Type:  "RSA PUBLIC KEY",
                Bytes: data,
            })

            return string(pemBytes)
        case EC2PublicKeyData:
            var curve elliptic.Curve

            switch COSEAlgorithmIdentifier(k.Algorithm) {
            case AlgES256:
                curve = elliptic.P256()
            case AlgES384:
                curve = elliptic.P384()
            case AlgES512:
                curve = elliptic.P521()
            default:
                return keyCannotDisplay
            }

            eKey := &ecdsa.PublicKey{
                Curve: curve,
                X:     big.NewInt(0).SetBytes(k.XCoord),
                Y:     big.NewInt(0).SetBytes(k.YCoord),
            }

            data, err := x509.MarshalPKIXPublicKey(eKey)
            if err != nil {
                return keyCannotDisplay
            }

            pemBytes := pem.EncodeToMemory(&pem.Block{
                Type:  "PUBLIC KEY",
                Bytes: data,
            })

            return string(pemBytes)
        case OKPPublicKeyData:
            if len(k.XCoord) != ed25519.PublicKeySize {
                return keyCannotDisplay
            }

            var oKey ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)

            copy(oKey, k.XCoord)

            data, err := MarshalEd25519PublicKey(oKey)
            if err != nil {
                return keyCannotDisplay
            }

            pemBytes := pem.EncodeToMemory(&pem.Block{
                Type:  "PUBLIC KEY",
                Bytes: data,
            })

            return string(pemBytes)

        default:
            return "Cannot display key of this type"
        }*/
    }
} // namespace WebAuthN::Protocol::WebAuthNCOSE

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP */
