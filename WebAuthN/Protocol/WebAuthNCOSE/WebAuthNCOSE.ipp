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
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol::WebAuthNCOSE {

    using json = nlohmann::json;

    // Consts

    inline const std::string KEY_CANNOT_DISPLAY = "Cannot display key";

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

    // Structs

    using HasherHandlerType = std::vector<uint8_t> (*)(const std::string& str);

    inline const struct {
        SignatureAlgorithmType algo;
        COSEAlgorithmIdentifierType coseAlg;
        std::string name;
        HasherHandlerType hasher;
    } SIGNATURE_ALGORITHM_DETAILS[] {
        { SignatureAlgorithmType::SHA1WithRSA,                 COSEAlgorithmIdentifierType::AlgRS1,      "SHA1-RSA",   crypto.SHA1.New },
        { SignatureAlgorithmType::SHA256WithRSA,             COSEAlgorithmIdentifierType::AlgRS256,    "SHA256-RSA", crypto.SHA256.New },
        { SignatureAlgorithmType::SHA384WithRSA,             COSEAlgorithmIdentifierType::AlgRS384,    "SHA384-RSA", crypto.SHA384.New },
        { SignatureAlgorithmType::SHA512WithRSA,             COSEAlgorithmIdentifierType::AlgRS512,    "SHA512-RSA", crypto.SHA512.New },
        { SignatureAlgorithmType::SHA256WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS256, "SHA256-RSAPSS", crypto.SHA256.New },
        { SignatureAlgorithmType::SHA384WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS384, "SHA384-RSAPSS", crypto.SHA384.New },
        { SignatureAlgorithmType::SHA512WithRSAPSS,          COSEAlgorithmIdentifierType::AlgPS512, "SHA512-RSAPSS", crypto.SHA512.New },
        { SignatureAlgorithmType::ECDSAWithSHA256,           COSEAlgorithmIdentifierType::AlgES256,  "ECDSA-SHA256", crypto.SHA256.New },
        { SignatureAlgorithmType::ECDSAWithSHA384,           COSEAlgorithmIdentifierType::AlgES384,  "ECDSA-SHA384", crypto.SHA384.New },
        { SignatureAlgorithmType::ECDSAWithSHA512,           COSEAlgorithmIdentifierType::AlgES512,  "ECDSA-SHA512", crypto.SHA512.New },
        { SignatureAlgorithmType::UnknownSignatureAlgorithm, COSEAlgorithmIdentifierType::AlgEdDSA,         "EdDSA", crypto.SHA512.New }
    };

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
        inline expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept {
            return true;
            /*var curve elliptic.Curve

            switch COSEAlgorithmIdentifier(Algorithm) {
            case AlgES512: // IANA COSE code for ECDSA w/ SHA-512.
                curve = elliptic.P521()
            case AlgES384: // IANA COSE code for ECDSA w/ SHA-384.
                curve = elliptic.P384()
            case AlgES256: // IANA COSE code for ECDSA w/ SHA-256.
                curve = elliptic.P256()
            default:
                return false, ErrUnsupportedAlgorithm
            }

            pubkey := &ecdsa.PublicKey{
                Curve: curve,
                X:     big.NewInt(0).SetBytes(k.XCoord),
                Y:     big.NewInt(0).SetBytes(k.YCoord),
            }

            type ECDSASignature struct {
                R, S *big.Int
            }

            e := &ECDSASignature{}
            f := HasherFromCOSEAlg(COSEAlgorithmIdentifier(Algorithm))
            h := f()

            h.Write(data)

            _, err := asn1.Unmarshal(sig, e)
            if err != nil {
                return false, ErrSigNotProvidedOrInvalid
            }

            return ecdsa.Verify(pubkey, h.Sum(nil), e.R, e.S), nil*/
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
        inline expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept {
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
        inline expected<bool>
        Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) const noexcept {
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

    // ParsePublicKey figures out what kind of COSE material was provided and create the data for the new key.
    inline expected<PublicKeyDataType&> ParsePublicKey(const std::vector<uint8_t>& keyBytes) noexcept {
        auto pk = PublicKeyDataType{};
        return pk;
        /*WebAuthNCBOR::Unmarshal(keyBytes, &pk);

        switch COSEKeyType(pk.KeyType) {
        case OctetKey:
            OKPPublicKeyDataType o{};
            WebAuthNCBOR::Unmarshal(keyBytes, &o);
            o.PublicKeyData = pk;

            return o, nil
        case EllipticKey:
            EC2PublicKeyDataType e{};

            WebAuthNCBOR::Unmarshal(keyBytes, &e);
            e.PublicKeyData = pk;

            return e, nil
        case RSAKey:
            RSAPublicKeyDataType r{};

            WebAuthNCBOR::Unmarshal(keyBytes, &r);
            r.PublicKeyData = pk;

            return r, nil
        default:
            return nil, ErrUnsupportedKey
        }*/
    }

    // ParseFIDOPublicKey is only used when the appID extension is configured by the assertion response.
    inline expected<EC2PublicKeyDataType> ParseFIDOPublicKey(const std::vector<uint8_t>& keyBytes) noexcept {
        return true;
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

    inline expected<bool> VerifySignature(const std::any& key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) {
        return true;
        /*switch k := key.(type) {
        case OKPPublicKeyData:
            return k.Verify(data, sig)
        case EC2PublicKeyData:
            return k.Verify(data, sig)
        case RSAPublicKeyData:
            return k.Verify(data, sig)
        default:
            return false, ErrUnsupportedKey
        }*/
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

    // Errors

    struct ErrUnsupportedKey : public ErrorType {

        ErrUnsupportedKey() noexcept :
            ErrorType(
                "invalid_key_type",
                "Unsupported Public Key Type") {
        }
    };
    
    struct ErrUnsupportedAlgorithm : public ErrorType {

        ErrUnsupportedAlgorithm() noexcept :
            ErrorType(
                "unsupported_key_algorithm",
                "Unsupported public key algorithm") {
        }
    };
    
    struct ErrSigNotProvidedOrInvalid : public ErrorType {

        ErrSigNotProvidedOrInvalid() noexcept :
            ErrorType(
                "signature_not_provided_or_invalid",
                "Signature invalid or not provided") {
        }
    };
} // namespace WebAuthN::Protocol::WebAuthNCOSE

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP */