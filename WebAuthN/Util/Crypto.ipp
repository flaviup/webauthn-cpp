//
//  Crypto.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/24/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_CRYPTO_IPP
#define WEBAUTHN_UTIL_CRYPTO_IPP

#include <algorithm>
#include <tuple>
#include <string>
#include <vector>
#include <sodium.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "../Core.ipp"
#include "SSLHostCheck/openssl_hostname_validation.h"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Crypto {

    using namespace std::string_literals;

    inline std::vector<uint8_t> SHA1(const std::string& str) {

        const constexpr auto HASH_SIZE_BYTES = 20U;
        unsigned char out[HASH_SIZE_BYTES];

        crypto_generichash(out,
                           HASH_SIZE_BYTES,
                           reinterpret_cast<const unsigned char*>(str.data()), str.size(),
                           nullptr, 
                           0);

        return std::vector<uint8_t>(out, out + HASH_SIZE_BYTES);
    }

    inline std::vector<uint8_t> SHA256(const unsigned char* str, const size_t size) {

        unsigned char out[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(out, str, size);

        return std::vector<uint8_t>(out, out + crypto_hash_sha256_BYTES);
    }

    inline std::vector<uint8_t> SHA256(const std::string& str) {

        return SHA256(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

    inline std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data) {

        return SHA256(data.data(), data.size());
    }

    inline std::vector<uint8_t> SHA384(const std::string& str) {

        const constexpr auto HASH_SIZE_BYTES = 48U;
        unsigned char out[HASH_SIZE_BYTES];

        crypto_generichash(out,
                           HASH_SIZE_BYTES,
                           reinterpret_cast<const unsigned char*>(str.data()), str.size(),
                           nullptr, 
                           0);

        return std::vector<uint8_t>(out, out + HASH_SIZE_BYTES);
    }

    inline std::vector<uint8_t> SHA512(const std::string& str) {

        unsigned char out[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(out, reinterpret_cast<const unsigned char*>(str.data()), str.size());

        return std::vector<uint8_t>(out, out + crypto_hash_sha512_BYTES);
    }

    struct X509CertificateType {

        struct SubjectType {

            std::string Country;
            std::string Organization;
            std::string OrganizationalUnit;
            std::string CommonName;
        } Subject;

        struct ExtensionType {

            std::string ID;
            std::vector<uint8_t> Value;
            bool IsCritical;
        };

        std::vector<ExtensionType> Extensions;

        std::string SignatureAlgorithm;

        std::string NotBefore;
        std::string NotAfter;

        long Version;
        bool IsCA;
    };

#pragma GCC visibility push(hidden)

    namespace {

        // Obtains an entry from a X509 name (i.e. either
        // the certificate’s issuer or subject)
        static inline expected<std::string>
        _ExtractNameEntry(const X509_NAME* name, int nid) noexcept {

            if (name == nullptr) {
                return unexpected("Null X509_NAME"s);
            }
            auto position = X509_NAME_get_index_by_NID(name, nid, -1);
            auto entry = X509_NAME_get_entry(name, position);

            if (entry == nullptr) {
                return unexpected("Null X509_NAME_ENTRY"s);
            }
            auto asn1Data = X509_NAME_ENTRY_get_data(entry);
            
            if (asn1Data == nullptr) {
                return unexpected("Null ASN1_STRING"s);
            }
            auto entryString = ASN1_STRING_get0_data(asn1Data);
            std::string s(reinterpret_cast<const char*>(entryString));

            return s;
        }

        static inline expected<std::string>
        _ConvertASN1TIME(const ASN1_TIME* t) noexcept {

            if (t == nullptr) {
                return unexpected("Null ASN1_TIME"s);
            }
            auto bio = BIO_new(BIO_s_mem());

            if (bio == nullptr) {
                return unexpected("Null BIO"s);
            }
            auto rc = ASN1_TIME_print(bio, t);
            
            if (rc <= 0) {

                BIO_free_all(bio);
                return unexpected("ASN1_TIME_print failed or wrote no data"s);
            }
            constexpr auto DATE_LEN = 128;
            char buf[DATE_LEN]{};
            rc = BIO_gets(bio, buf, DATE_LEN);

            if (rc <= 0) {

                BIO_free_all(bio);
                return unexpected("BIO_gets call failed to transfer contents to buf"s);
            }
            BIO_free_all(bio);

            return std::string(buf);
        }

        static inline expected<X509CertificateType::ExtensionType>
        _GetExtension(const stack_st_X509_EXTENSION* extensions, const int index) noexcept {

            if (extensions == nullptr) {
                return unexpected("Null stack_st_X509_EXTENSION"s);
            }
            auto extension = sk_X509_EXTENSION_value(extensions, index);

            if (extension == nullptr) {
                return unexpected("Unable to extract extension from stack"s);
            }
            auto obj = X509_EXTENSION_get_object(extension);

            if (obj == nullptr) {
                return unexpected("Unable to extract ASN1 object from extension"s);
            }
            X509CertificateType::ExtensionType parsedExtension{};
            parsedExtension.IsCritical = X509_EXTENSION_get_critical(extension) != 0;
            auto nid = OBJ_obj2nid(obj);

            if (nid == NID_undef) {

                // no lookup found for the provided OID so nid came back as undefined.
                const auto size = OBJ_obj2txt(nullptr, 0, obj, 0);

                if (size < 0) {
                    return unexpected("Invalid extension name length"s);
                }
                char* extensionName = new char[size + 1]{0};
                OBJ_obj2txt(extensionName, size + 1, obj, 0);
                parsedExtension.ID = extensionName;
                delete [] extensionName;
            } else {

                // the OID translated to a NID which implies that the OID has a known sn/ln
                auto extensionName = OBJ_nid2ln(nid);

                if (extensionName == nullptr) {
                    return unexpected("Invalid X509v3 extension name"s);
                }
                parsedExtension.ID = extensionName;
            }
            auto ex = X509_EXTENSION_get_data(extension);

            if (ex != nullptr) {
                parsedExtension.Value = std::vector<uint8_t>(ex->data, ex->data + ex->length);
            }

            if (parsedExtension.ID.empty() && parsedExtension.Value.empty()) {
                return unexpected("Could not parse X509_EXTENSION"s);
            }

            return parsedExtension;
        }

        static inline expected<bool>
        _CheckSignature(const X509* certificate,
                        const std::string& algorithmName,
                        const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& signature) noexcept {

            if (certificate == nullptr) {
                return unexpected("Null X509 certificate"s);
            }
            auto pKey = X509_get0_pubkey(certificate);
            
            if (pKey == nullptr) {
                return unexpected("Could not get the public key from certificate"s);
            }
            auto mdCtx = EVP_MD_CTX_new();

            if (mdCtx == nullptr) {
                return unexpected("Could not create MD context"s);
            }
            auto result = EVP_DigestVerifyInit_ex(mdCtx, nullptr, algorithmName.c_str(), nullptr, nullptr, pKey, nullptr);

            if (result != 1) {

                EVP_MD_CTX_free(mdCtx);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, signature.data(), signature.size(), data.data(), data.size());
            EVP_MD_CTX_free(mdCtx);

            if (result == 0 || result == 1) {
                return result == 1;
            }

            return unexpected("Could not check signature"s);
        }
    }

#pragma GCC visibility pop

    inline expected<std::tuple<std::string, std::string>>
    GetNamesX509(const std::vector<uint8_t>& data) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, data.data(), static_cast<int>(data.size())) != static_cast<int>(data.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not get names from X509 certificate"s);
        }
        auto subject = X509_get_subject_name(certificate);
        auto issuer = X509_get_issuer_name(certificate);

        auto subjectNameResult = _ExtractNameEntry(subject, NID_commonName);
        auto issuerNameResult  = _ExtractNameEntry(issuer, NID_commonName);

        X509_free(certificate);
        BIO_free_all(bio);

        if (!subjectNameResult) {
            return unexpected(subjectNameResult.error());
        }

        if (!issuerNameResult) {
            return unexpected(issuerNameResult.error());
        }

        return std::make_pair(subjectNameResult.value(), issuerNameResult.value());
    }

    inline expected<X509CertificateType>
    ParseCertificate(const std::vector<uint8_t>& data) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, data.data(), static_cast<int>(data.size())) != static_cast<int>(data.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }
        X509CertificateType parsedCertificate{};
        auto subject = X509_get_subject_name(certificate);

        if (subject != nullptr) {

            auto countryResult = _ExtractNameEntry(subject, NID_countryName);
            auto organizationResult = _ExtractNameEntry(subject, NID_organizationName);
            auto organizationalUnitResult = _ExtractNameEntry(subject, NID_organizationalUnitName);
            auto commonNameResult = _ExtractNameEntry(subject, NID_commonName);

            parsedCertificate.Subject.Country = countryResult ? countryResult.value() : "";
            parsedCertificate.Subject.Organization = organizationResult ? organizationResult.value() : "";
            parsedCertificate.Subject.OrganizationalUnit = organizationalUnitResult ? organizationalUnitResult.value() : "";
            parsedCertificate.Subject.CommonName = commonNameResult ? commonNameResult.value() : "";
        }
        auto extensions = X509_get0_extensions(certificate);
        int extCount{};
        extCount = (extensions != nullptr) ? sk_X509_EXTENSION_num(extensions) : 0;

        if (extCount < 0) {

            X509_free(certificate);
            BIO_free_all(bio);

            return unexpected("Could not parse X509 certificate: invalid number of extensions"s);
        }

        for (int i = 0; i < extCount; ++i) {

            auto extensionResult = _GetExtension(extensions, i);

            if (extensionResult) {
                parsedCertificate.Extensions.push_back(extensionResult.value());
            }            
        }
        auto notBefore = X509_get0_notBefore(certificate);
        auto notAfter = X509_get0_notAfter(certificate);

        if (notBefore != nullptr) {

            auto conversionResult = _ConvertASN1TIME(notBefore);

            if (!conversionResult) {

                X509_free(certificate);
                BIO_free_all(bio);

                return unexpected(conversionResult.error());
            }
            parsedCertificate.NotBefore = conversionResult.value();
        }

        if (notAfter != nullptr) {

            auto conversionResult = _ConvertASN1TIME(notAfter);

            if (!conversionResult) {

                X509_free(certificate);
                BIO_free_all(bio);

                return unexpected(conversionResult.error());
            }
            parsedCertificate.NotAfter = conversionResult.value();
        }
        parsedCertificate.Version = X509_get_version(certificate);
        parsedCertificate.IsCA = X509_check_ca(certificate) > 0;

        X509_free(certificate);
        BIO_free_all(bio);

        return parsedCertificate;
    }

    inline expected<bool>
    CheckSignature(const std::vector<uint8_t>& certData,
                   const std::string& algorithmName,
                   const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& signature) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, certData.data(), static_cast<int>(certData.size())) != static_cast<int>(certData.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }
        auto result = _CheckSignature(certificate, algorithmName, data, signature);
        
        X509_free(certificate);
        BIO_free_all(bio);

        return result;
    }

    inline expected<std::string>
    ParseCertificatePublicKey(const std::vector<uint8_t>& certData) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, certData.data(), static_cast<int>(certData.size())) != static_cast<int>(certData.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }
        auto pKey = X509_get0_pubkey(certificate);
            
        if (pKey == nullptr) {

            X509_free(certificate);
            BIO_free_all(bio);

            return unexpected("Could not get the public key from certificate"s);
        }
        auto bioKey = BIO_new(BIO_s_mem());
        
        if (bioKey == nullptr) {

            X509_free(certificate);
            BIO_free_all(bio);

            return unexpected("Null BIO"s);
        }
        const char* p = nullptr;
        long size = 0;
        auto s = ""s;
        auto ok = false;

        if (PEM_write_bio_PUBKEY(bioKey, pKey) == 1) {

            BIO_flush(bioKey);
            size = BIO_get_mem_data(bioKey, &p);
            ok = true;
        }

        if (p != nullptr) {
            s = std::string(p, p + size);
        }

        BIO_free_all(bioKey);
        X509_free(certificate);
        BIO_free_all(bio);

        if (!ok && p == nullptr) {
            return unexpected("PEM_write_bio_PUBKEY failed"s);
        }

        return s;
    }

    using ECPublicKeyInfo = std::tuple<int, std::optional<int>, std::optional<std::vector<uint8_t>>, std::optional<std::vector<uint8_t>>>;

    inline expected<ECPublicKeyInfo>
    ParseCertificateECPublicKeyInfo(const std::vector<uint8_t>& certData) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, certData.data(), static_cast<int>(certData.size())) != static_cast<int>(certData.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }
        auto pKey = X509_get0_pubkey(certificate);
            
        if (pKey == nullptr) {

            X509_free(certificate);
            BIO_free_all(bio);

            return unexpected("Could not get the EC public key from certificate"s);
        }
        auto algo = 0;
        std::optional<int> curve = std::nullopt;
        char curveName[64]{0};
        size_t size = 0;

        if (EVP_PKEY_get_utf8_string_param(pKey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           curveName, sizeof(curveName), &size) == 1) {

            char CURVE_P521[] = "P-521";
            char CURVE_P384[] = "P-384";
            char CURVE_P256[] = "P-256";

            if (strcmp(curveName, CURVE_P521) == 0) {
                curve = NID_secp521r1;
                algo = NID_ecdsa_with_SHA512;
            } else if (strcmp(curveName, CURVE_P384) == 0) {
                curve = NID_secp384r1;
                algo = NID_ecdsa_with_SHA384;
            } else if (strcmp(curveName, CURVE_P256) == 0) {
                curve = NID_secp256k1;
                algo = NID_secp256k1;
            }
        }
        std::optional<std::vector<uint8_t>> x = std::nullopt;
        BIGNUM* bnX = nullptr;

        if (EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_EC_PUB_X, &bnX) == 1) {

            uint8_t buff[BN_num_bytes(bnX)];
            auto length = BN_bn2bin(bnX, buff);
            x = std::vector<uint8_t>(buff, buff + length);
        }
        std::optional<std::vector<uint8_t>> y = std::nullopt;
        BIGNUM* bnY = nullptr;

        if (EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_EC_PUB_X, &bnY) == 1) {

            uint8_t buff[BN_num_bytes(bnY)];
            auto length = BN_bn2bin(bnY, buff);
            y = std::vector<uint8_t>(buff, buff + length);
        }

        if (bnX != nullptr) {
            BN_clear_free(bnX);
        }

        if (bnY != nullptr) {
            BN_clear_free(bnY);
        }

        X509_free(certificate);
        BIO_free_all(bio);

        return ECPublicKeyInfo{
            algo,
            curve,
            x,
            y
        };
    }

    inline expected<bool>
    VerifyCertificateHostname(const std::vector<uint8_t>& certData, const char* hostname) noexcept {

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {
            return unexpected("Null BIO"s);
        }

        if (BIO_write(bio, certData.data(), static_cast<int>(certData.size())) != static_cast<int>(certData.size())) {

            BIO_free_all(bio);
            return unexpected("Could not duplicate certificate data"s);
        }
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }
        auto result = validate_hostname(hostname, certificate);

        X509_free(certificate);
        BIO_free_all(bio);

        if (result == MatchFound) {
            return true;
        } else if (result == MatchNotFound) {
            return false;
        }

        return unexpected("Error verifying certificate hostname"s);
    }
} // namespace WebAuthN::Util::Crypto

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CRYPTO_IPP */
