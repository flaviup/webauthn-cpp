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
#include <string>
#include <vector>
#include <sodium.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../Core.ipp"

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

    inline std::vector<uint8_t> SHA256(const std::string& str) {

        unsigned char out[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(out, reinterpret_cast<const unsigned char*>(str.data()), str.size());

        return std::vector<uint8_t>(out, out + crypto_hash_sha256_BYTES);
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
        inline expected<std::string> _ExtractNameEntry(const X509_NAME* name, int nid) noexcept {

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

                X509_NAME_ENTRY_free(entry);
                return unexpected("Null ASN1_STRING"s);
            }
            auto entryString = ASN1_STRING_get0_data(asn1Data);
            std::string s(reinterpret_cast<const char*>(entryString));

            ASN1_STRING_clear_free(asn1Data);
            X509_NAME_ENTRY_free(entry);

            return s;
        }

        inline expected<std::string> _ConvertASN1TIME(const ASN1_TIME* t) noexcept {

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

        inline expected<X509CertificateType::ExtensionType> _GetExtension(const stack_st_X509_EXTENSION* extensions, const int index) noexcept {

            if (extensions == nullptr) {

                return unexpected("Null stack_st_X509_EXTENSION"s);
            }
            auto extension = sk_X509_EXTENSION_value(extensions, index);

            if (extension == nullptr) {

                return unexpected("Unable to extract extension from stack"s);
            }
            auto obj = X509_EXTENSION_get_object(extension);

            if (obj == nullptr) {

                X509_EXTENSION_free(extension);
                return unexpected("Unable to extract ASN1 object from extension"s);
            }
            X509CertificateType::ExtensionType parsedExtension{};
            parsedExtension.IsCritical = X509_EXTENSION_get_critical(extension) != 0;

            auto nid = OBJ_obj2nid(obj);

            if (nid == NID_undef) {

                // no lookup found for the provided OID so nid came back as undefined.
                const auto size = OBJ_obj2txt(nullptr, 0, obj, 0);

                if (size < 0) {

                    ASN1_OBJECT_free(obj);
                    X509_EXTENSION_free(extension);
                    OBJ_cleanup();
                    return unexpected("Invalid extension name length"s);
                }
                char* extensionName = new char[size + 2]{0};
                OBJ_obj2txt(extensionName, size, obj, 0);
                parsedExtension.ID = extensionName;
                delete [] extensionName;
            } else {

                // the OID translated to a NID which implies that the OID has a known sn/ln
                auto extensionName = OBJ_nid2ln(nid);

                if (extensionName == nullptr) {

                    ASN1_OBJECT_free(obj);
                    X509_EXTENSION_free(extension);
                    OBJ_cleanup();

                    return unexpected("Invalid X509v3 extension name"s);
                }
                parsedExtension.ID = extensionName;
            }
            auto ex = reinterpret_cast<ASN1_OCTET_STRING*>(X509V3_EXT_d2i(extension));

            if (ex != nullptr) {

                parsedExtension.Value = std::vector<uint8_t>(ex->data, ex->data + ex->length);
                ASN1_OCTET_STRING_free(ex);
            } else {

                ASN1_OBJECT_free(obj);
                X509_EXTENSION_free(extension);
                OBJ_cleanup();

                return unexpected("Could not parse X509_EXTENSION: X509V3_EXT_d2i failure"s);
            }

            ASN1_OBJECT_free(obj);
            X509_EXTENSION_free(extension);
            OBJ_cleanup();

            return parsedExtension;
        }

        inline expected<bool>
        _CheckSignature(const X509* certificate,
                        const std::string& algorithm,
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

                EVP_PKEY_free(pKey);
                return unexpected("Could not create MD context"s);
            }
            auto result = EVP_DigestVerifyInit_ex(mdCtx, nullptr, algorithm.c_str(), nullptr, nullptr, pKey, nullptr);

            if (result != 1) {

                EVP_MD_CTX_free(mdCtx);
                EVP_PKEY_free(pKey);
                return unexpected("Unable to init signature checking"s);
            }
            result = EVP_DigestVerify(mdCtx, signature.data(), signature.size(), data.data(), data.size());
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(pKey);

            if (result == 0 || result == 1) {

                return result == 1;
            } else {

                return unexpected("Could not check signature");
            }
        }
    }

#pragma GCC visibility pop

    inline expected<std::pair<std::string, std::string>> GetNamesX509(const std::vector<uint8_t>& data) noexcept {

        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {

            return unexpected("Null BIO"s);
        }
        BIO_puts(bio, reinterpret_cast<const char*>(data.data()));
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

        if (subject != nullptr) {
            
            X509_NAME_free(subject);
        }

        if (issuer != nullptr) {
        
            X509_NAME_free(issuer);
        }

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

    inline expected<X509CertificateType> ParseCertificate(const std::vector<uint8_t>& data) noexcept {

        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {

            return unexpected("Null BIO"s);
        }
        BIO_puts(bio, reinterpret_cast<const char*>(data.data()));
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

            X509_NAME_free(subject);
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
                   const std::string& algorithm,
                   const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& signature) noexcept {

        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        auto bio = BIO_new(BIO_s_mem());

        if (bio == nullptr) {

            return unexpected("Null BIO"s);
        }
        BIO_puts(bio, reinterpret_cast<const char*>(data.data()));
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free_all(bio);
            return unexpected("Could not parse X509 certificate"s);
        }

        auto result = _CheckSignature(certificate, algorithm, data, signature);
        
        X509_free(certificate);
        BIO_free_all(bio);

        return result;
    }
} // namespace WebAuthN::Util::Crypto

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CRYPTO_IPP */
