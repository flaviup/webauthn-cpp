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

        explicit inline operator std::string() const {
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

    inline const ErrorType ErrBadRequest{
		"invalid_request",
		"Error reading the request data"
	};

	inline const ErrorType ErrChallengeMismatch{
		"challenge_mismatch",
		"Stored challenge and received challenge do not match"
	};
	
	inline const ErrorType ErrParsingData{
		"parse_error",
		"Error parsing the authenticator response"
	};
	
	inline const ErrorType ErrAuthData{
		"auth_data",
		"Error verifying the authenticator data"
	};
	
	inline const ErrorType ErrVerification{
		"verification_error",
		"Error validating the authenticator response"
	};
	
	inline const ErrorType ErrAttestation{
		"attestation_error",
		"Error validating the attestation data provided"
	};
	
	inline const ErrorType ErrInvalidAttestation{
		"invalid_attestation",
		"Invalid attestation data"
	};
	
	inline const ErrorType ErrAttestationFormat{
		"invalid_attestation",
		"Invalid attestation format"
	};
	
	inline const ErrorType ErrAttestationCertificate{
		"invalid_certificate",
		"Invalid attestation certificate"
	};
	
	inline const ErrorType ErrAssertionSignature{
		"invalid_signature",
		"Assertion Signature against auth data and client hash is not valid"
	};
	
	inline const ErrorType ErrUnsupportedKey{
		"invalid_key_type",
		"Unsupported Public Key Type"
	};
	
	inline const ErrorType ErrUnsupportedAlgorithm{
		"unsupported_key_algorithm",
		"Unsupported public key algorithm"
	};

	inline const ErrorType ErrNotSpecImplemented{
		"spec_unimplemented",
		"This field is not yet supported by the WebAuthn spec"
	};
	
	inline const ErrorType ErrNotImplemented{
		"not_implemented",
		"This field is not yet supported by this library",
	};
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ERRORS_IPP */
