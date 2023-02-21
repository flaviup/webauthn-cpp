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
        ErrorType(std::string&& type, std::string&& details) :
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

        inline ErrorType& WithDetails(const std::string& details) {
            
            Details = details;
            return *this;
        }

        inline ErrorType& WithInfo(const std::string& info) {
            
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

    class ErrBadRequest : public ErrorType {
		ErrBadRequest() :
		ErrorType(
			"invalid_request",
			"Error reading the request data") {
		}
	};

	class ErrChallengeMismatch : public ErrorType {
		ErrChallengeMismatch() :
		ErrorType(
			"challenge_mismatch",
			"Stored challenge and received challenge do not match") {
		}
	};
	
	class ErrParsingData : public ErrorType {
		ErrParsingData() :
		ErrorType(
			"parse_error",
			"Error parsing the authenticator response") {
		}
	};
	
	class ErrAuthData : public ErrorType {
		ErrAuthData() :
		ErrorType(
			"auth_data",
			"Error verifying the authenticator data") {
		}
	};
	
	class ErrVerification : public ErrorType {
		ErrVerification() :
		ErrorType(
			"verification_error",
			"Error validating the authenticator response") {
		}
	};
	
	class ErrAttestation : public ErrorType {
		ErrAttestation() :
		ErrorType(
			"attestation_error",
			"Error validating the attestation data provided") {
		}
	};
	
	class ErrInvalidAttestation : public ErrorType {
		ErrInvalidAttestation() :
		ErrorType(
			"invalid_attestation",
			"Invalid attestation data") {
		}
	};
	
	class ErrAttestationFormat : public ErrorType {
		ErrAttestationFormat() :
		ErrorType(
			"invalid_attestation",
			"Invalid attestation format") {
		}
	};
	
	class ErrAttestationCertificate : public ErrorType {
		ErrAttestationCertificate() :
		ErrorType(
			"invalid_certificate",
			"Invalid attestation certificate") {
		}
	};
	
	class ErrAssertionSignature : public ErrorType {
		ErrAssertionSignature() :
		ErrorType(
			"invalid_signature",
			"Assertion Signature against auth data and client hash is not valid") {
		}
	};
	
	class ErrUnsupportedKey : public ErrorType {
		ErrUnsupportedKey() :
		ErrorType(
			"invalid_key_type",
			"Unsupported Public Key Type") {
		}
	};
	
	class ErrUnsupportedAlgorithm : public ErrorType {
		ErrUnsupportedAlgorithm() :
		ErrorType(
			"unsupported_key_algorithm",
			"Unsupported public key algorithm") {
		}
	};

	class ErrNotSpecImplemented : public ErrorType {
		ErrNotSpecImplemented() :
		ErrorType(
			"spec_unimplemented",
			"This field is not yet supported by the WebAuthn spec") {
		}
	};
	
	class ErrNotImplemented : public ErrorType {
		ErrNotImplemented() :
		ErrorType(
			"not_implemented",
			"This field is not yet supported by this library") {
		}
	};
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ERRORS_IPP */
