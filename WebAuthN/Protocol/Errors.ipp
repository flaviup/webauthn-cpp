//
//  Errors.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ERRORS_IPP
#define WEBAUTHN_PROTOCOL_ERRORS_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "Base64.ipp"
#include "Extensions.ipp"
#include "../../expected.hh"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    struct ErrorType {

        ErrorType() noexcept = default;
        ErrorType(std::string&& type, std::string&& details) noexcept :
            Type(std::move(type)),
            Details(std::move(details)) {
        }
        ErrorType(const json& j) :
            Type(j["type"].get<std::string>()),
            Details(j["error"].get<std::string>()),
            DevInfo(j["debug"].get<std::string>()) {
        }

        explicit inline operator std::string() const noexcept {

            return Details; 
        }

        inline ErrorType& WithDetails(const std::string& details) noexcept {
            
            Details = details;
            return *this;
        }

        inline ErrorType& WithInfo(const std::string& info) noexcept {
            
            DevInfo = info;
            return *this;
        }

        // Short name for the type of error that has occurred.
        std::string Type;
        // Additional details about the error.
        std::string Details;
        // Information to help debug the error.
        std::string DevInfo;
    };

    void to_json(json& j, const ErrorType& error) {

        j = json{
            {"type", error.Type}, 
            {"error", error.Details}, 
            {"debug", error.DevInfo}
        };
    }

    void from_json(const json& j, ErrorType& error) {

        j.at("type").get_to(error.Type);
        j.at("error").get_to(error.Details);
        j.at("debug").get_to(error.DevInfo);
    }

    struct ErrBadRequest : public ErrorType {

		ErrBadRequest() noexcept :
		ErrorType(
			"invalid_request",
			"Error reading the request data") {
		}
	};

	struct ErrChallengeMismatch : public ErrorType {

		ErrChallengeMismatch() noexcept :
		ErrorType(
			"challenge_mismatch",
			"Stored challenge and received challenge do not match") {
		}
	};
	
	struct ErrParsingData : public ErrorType {

		ErrParsingData() noexcept :
		ErrorType(
			"parse_error",
			"Error parsing the authenticator response") {
		}
	};
	
	struct ErrAuthData : public ErrorType {

		ErrAuthData() noexcept :
		ErrorType(
			"auth_data",
			"Error verifying the authenticator data") {
		}
	};
	
	struct ErrVerification : public ErrorType {

		ErrVerification() noexcept :
		ErrorType(
			"verification_error",
			"Error validating the authenticator response") {
		}
	};
	
	struct ErrAttestation : public ErrorType {

		ErrAttestation() noexcept :
		ErrorType(
			"attestation_error",
			"Error validating the attestation data provided") {
		}
	};
	
	struct ErrInvalidAttestation : public ErrorType {

		ErrInvalidAttestation() noexcept :
		ErrorType(
			"invalid_attestation",
			"Invalid attestation data") {
		}
	};
	
	struct ErrAttestationFormat : public ErrorType {

		ErrAttestationFormat() noexcept :
		ErrorType(
			"invalid_attestation",
			"Invalid attestation format") {
		}
	};
	
	struct ErrAttestationCertificate : public ErrorType {

		ErrAttestationCertificate() noexcept :
		ErrorType(
			"invalid_certificate",
			"Invalid attestation certificate") {
		}
	};
	
	struct ErrAssertionSignature : public ErrorType {

		ErrAssertionSignature() noexcept :
		ErrorType(
			"invalid_signature",
			"Assertion Signature against auth data and client hash is not valid") {
		}
	};
	
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

	struct ErrNotSpecImplemented : public ErrorType {

		ErrNotSpecImplemented() noexcept :
		ErrorType(
			"spec_unimplemented",
			"This field is not yet supported by the WebAuthn spec") {
		}
	};
	
	struct ErrNotImplemented : public ErrorType {

		ErrNotImplemented() noexcept :
		ErrorType(
			"not_implemented",
			"This field is not yet supported by this library") {
		}
	};
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ERRORS_IPP */
