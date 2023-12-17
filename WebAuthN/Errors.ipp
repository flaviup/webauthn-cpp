//
//  Errors.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_ERRORS_IPP
#define WEBAUTHN_ERRORS_IPP

#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "../libUtilCpp/Error.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN {

    using json = nlohmann::json;
    using IError = UtilCpp::IError;
    using ErrorType = UtilCpp::Error;

    inline void to_json(json& j, const ErrorType& error) {

        j = json{
            { "type",     error.GetType() },
            { "error", error.GetDetails() },
            { "debug",    error.GetInfo() }
        };
    }

    inline void from_json(const json& j, ErrorType& error) {
        error = ErrorType(j.at("type").get<std::string>(), j.at("error").get<std::string>()).WithInfo(j.at("debug").get<std::string>());
    }

    struct ErrBadRequest final : public ErrorType {

        ErrBadRequest() noexcept :
            ErrorType(
                "invalid_request",
                "Error reading the request data") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrChallengeMismatch final : public ErrorType {

        ErrChallengeMismatch() noexcept :
            ErrorType(
                "challenge_mismatch",
                "Stored challenge and received challenge do not match") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrParsingData final : public ErrorType {

        ErrParsingData() noexcept :
            ErrorType(
                "parse_error",
                "Error parsing the authenticator response") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrAuthData : public ErrorType {

        ErrAuthData() noexcept :
            ErrorType(
                "auth_data",
                "Error verifying the authenticator data") {
        }
    };

    struct ErrVerification final : public ErrorType {

        ErrVerification() noexcept :
            ErrorType(
                "verification_error",
                "Error validating the authenticator response") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrAttestation : public ErrorType {

        ErrAttestation() noexcept :
            ErrorType(
                "attestation_error",
                "Error validating the attestation data provided") {
        }
    };

    struct ErrInvalidAttestation final : public ErrorType {

        ErrInvalidAttestation() noexcept :
            ErrorType(
                "invalid_attestation",
                "Invalid attestation data") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrAttestationFormat final : public ErrorType {

        ErrAttestationFormat() noexcept :
            ErrorType(
                "invalid_attestation",
                "Invalid attestation format") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrAttestationCertificate final : public ErrorType {

        ErrAttestationCertificate() noexcept :
            ErrorType(
                "invalid_certificate",
                "Invalid attestation certificate") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrAssertionSignature final : public ErrorType {

        ErrAssertionSignature() noexcept :
            ErrorType(
                "invalid_signature",
                "Assertion Signature against auth data and client hash is not valid") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrUnsupportedKey final : public ErrorType {

        ErrUnsupportedKey() noexcept :
            ErrorType(
                "invalid_key_type",
                "Unsupported Public Key Type") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrUnsupportedAlgorithm final : public ErrorType {

        ErrUnsupportedAlgorithm() noexcept :
            ErrorType(
                "unsupported_key_algorithm",
                "Unsupported public key algorithm") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrNotSpecImplemented final : public ErrorType {

        ErrNotSpecImplemented() noexcept :
            ErrorType(
                "spec_unimplemented",
                "This field is not yet supported by the WebAuthn spec") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };

    struct ErrNotImplemented final : public ErrorType {

        ErrNotImplemented() noexcept :
            ErrorType(
                "not_implemented",
                "This field is not yet supported by this library") {
        }

        static void Id() noexcept {}

        uintptr_t GetClassId() const noexcept override {
            return reinterpret_cast<uintptr_t>(Id);
        }
    };
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_ERRORS_IPP */
