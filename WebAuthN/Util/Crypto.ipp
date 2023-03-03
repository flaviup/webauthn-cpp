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
#include <openssl/bio.h>
#include <openssl/x509.h>

#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::Crypto {

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


#pragma GCC visibility push(hidden)

    namespace {

        // Obtains an entry from a X509 name (i.e. either
        // the certificate’s issuer or subject)
        inline std::string _ExtractNameEntry(X509_NAME* name, int nid) {

            auto position = X509_NAME_get_index_by_NID(name, nid, -1);
            auto entry = X509_NAME_get_entry(name, position);

            ASN1_STRING* asn1Data = X509_NAME_ENTRY_get_data(entry);
            auto entryString = ASN1_STRING_get0_data(asn1Data);
            std::string s(reinterpret_cast<const char*>(entryString));

            ASN1_STRING_clear_free(asn1Data);
            X509_NAME_ENTRY_free(entry);

            return s;
        }
    }

#pragma GCC visibility pop

    inline expected<std::pair<std::string, std::string>> GetNamesX509(const std::vector<uint8_t>& data) {

        auto bio = BIO_new(BIO_s_mem());
        BIO_puts(bio, reinterpret_cast<const char*>(data.data()));
        X509* certificate = nullptr;
        d2i_X509_bio(bio, &certificate);

        if (certificate == nullptr) {

            BIO_free(bio);
            return unexpected(std::string("Could not get names from X509 certificate"));
        }

        auto subject = X509_get_subject_name(certificate);
        auto issuer = X509_get_issuer_name(certificate);

        auto subjectName = _ExtractNameEntry(subject, NID_commonName);
        auto issuerName  = _ExtractNameEntry(issuer, NID_commonName);
        auto names = std::make_pair(subjectName, issuerName);

        X509_NAME_free(subject);
        X509_NAME_free(issuer);

        X509_free(certificate);
        BIO_free(bio);

        return names;
    }

    struct X509CertificateType {

    };

    inline expected<X509CertificateType> ParseCertificate(const std::vector<uint8_t> data) {

    }
} // namespace WebAuthN::Util::Crypto

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_CRYPTO_IPP */
