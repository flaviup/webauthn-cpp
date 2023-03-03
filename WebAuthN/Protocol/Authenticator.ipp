//
//  Authenticator.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/20/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_AUTHENTICATOR_IPP
#define WEBAUTHN_PROTOCOL_AUTHENTICATOR_IPP

#include <cstddef>
#include <fmt/format.h>
#include "Core.ipp"
#include "WebAuthNCBOR/WebAuthNCBOR.ipp"
#include "../Util/Endianness.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // Consts

    inline constexpr const size_t MIN_AUTH_DATA_LENGTH = 37;
    inline constexpr const size_t MIN_ATTESTED_AUTH_LENGTH = 55;
    inline constexpr const size_t MAX_CREDENTIAL_ID_LENGTH = 1023;

    // Enums

    // AuthenticatorAttachmentType represents the IDL enum of the same name, and is used as part of the Authenticator Selection
    // Criteria.
    //
    // This enumeration’s values describe authenticators' attachment modalities. Relying Parties use this to express a
    // preferred authenticator attachment modality when calling navigator.credentials.create() to create a credential.
    //
    // If this member is present, eligible authenticators are filtered to only authenticators attached with the specified
    // §5.4.5 Authenticator Attachment Enumeration (enum AuthenticatorAttachment). The value SHOULD be a member of
    // AuthenticatorAttachment but client platforms MUST ignore unknown values, treating an unknown value as if the member
    // does not exist.
    //
    // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-authenticatorattachment)
    //
    // Specification: §5.4.5. Authenticator Attachment Enumeration (https://www.w3.org/TR/webauthn/#enum-attachment)
    enum class AuthenticatorAttachmentType {

        // Platform represents a platform authenticator is attached using a client device-specific transport, called
        // platform attachment, and is usually not removable from the client device. A public key credential bound to a
        // platform authenticator is called a platform credential.
        Platform,

        // CrossPlatform represents a roaming authenticator is attached using cross-platform transports, called
        // cross-platform attachment. Authenticators of this class are removable from, and can "roam" among, client devices.
        // A public key credential bound to a roaming authenticator is called a roaming credential.
        CrossPlatform,

        // Invalid value
        Invalid = -1
    };

    // map AuthenticatorAttachmentType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticatorAttachmentType, {
        { AuthenticatorAttachmentType::Invalid,                nullptr },
        { AuthenticatorAttachmentType::Invalid,                     "" },
        { AuthenticatorAttachmentType::Platform,            "platform" },
        { AuthenticatorAttachmentType::CrossPlatform, "cross-platform" }
    })

    // ResidentKeyRequirementType represents the IDL of the same name.
    //
    // This enumeration’s values describe the Relying Party's requirements for client-side discoverable credentials
    // (formerly known as resident credentials or resident keys).
    //
    // Specifies the extent to which the Relying Party desires to create a client-side discoverable credential. For
    // historical reasons the naming retains the deprecated “resident” terminology. The value SHOULD be a member of
    // ResidentKeyRequirement but client platforms MUST ignore unknown values, treating an unknown value as if the member
    // does not exist. If no value is given then the effective value is required if requireResidentKey is true or
    // discouraged if it is false or absent.
    //
    // Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-residentkey)
    //
    // Specification: §5.4.6. Resident Key Requirement Enumeration (https://www.w3.org/TR/webauthn/#enumdef-residentkeyrequirement)
    enum class ResidentKeyRequirementType {

        // Discouraged indicates the Relying Party prefers creating a server-side credential, but will
        // accept a client-side discoverable credential. This is the default.
        Discouraged,

        // Preferred indicates to the client we would prefer a discoverable credential.
        Preferred,

        // Required indicates the Relying Party requires a client-side discoverable credential, and is
        // prepared to receive an error if a client-side discoverable credential cannot be created.
        Required,

        // Invalid value
        Invalid = -1
    };

    // map ResidentKeyRequirementType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(ResidentKeyRequirementType, {
        { ResidentKeyRequirementType::Invalid,           nullptr },
        { ResidentKeyRequirementType::Invalid,                "" },
        { ResidentKeyRequirementType::Discouraged, "discouraged" },
        { ResidentKeyRequirementType::Preferred,     "preferred" },
        { ResidentKeyRequirementType::Required,       "required" }
    })

    // AuthenticatorTransportType represents the IDL enum with the same name.
    //
    // Authenticators may implement various transports for communicating with clients. This enumeration defines hints as to
    // how clients might communicate with a particular authenticator in order to obtain an assertion for a specific
    // credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may
    // be reached. A Relying Party will typically learn of the supported transports for a public key credential via
    // getTransports().
    //
    // Specification: §5.8.4. Authenticator Transport Enumeration (https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport)
    enum class AuthenticatorTransportType {

        // USB indicates the respective authenticator can be contacted over removable USB.
        USB,

        // NFC indicates the respective authenticator can be contacted over Near Field Communication (NFC).
        NFC,

        // BLE indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
        BLE,

        // Hybrid indicates the respective authenticator can be contacted using a combination of (often separate)
        // data-transport and proximity mechanisms. This supports, for example, authentication on a desktop computer using
        // a smartphone.
        //
        // WebAuthn Level 3.
        Hybrid,

        // Internal indicates the respective authenticator is contacted using a client device-specific transport, i.e., it
        // is a platform authenticator. These authenticators are not removable from the client device.
        Internal,

        // Invalid value
        Invalid = -1
    };

    // map AuthenticatorTransportType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(AuthenticatorTransportType, {
        { AuthenticatorTransportType::Invalid,     nullptr },
        { AuthenticatorTransportType::Invalid,          "" },
        { AuthenticatorTransportType::USB,           "usb" },
        { AuthenticatorTransportType::NFC,           "nfc" },
        { AuthenticatorTransportType::BLE,           "ble" },
        { AuthenticatorTransportType::Hybrid,     "hybrid" },
        { AuthenticatorTransportType::Internal, "internal" }
    })

    // UserVerificationRequirementType is a representation of the UserVerificationRequirement IDL enum.
    //
    // A WebAuthn Relying Party may require user verification for some of its operations but not for others,
    // and may use this type to express its needs.
    //
    // Specification: §5.8.6. User Verification Requirement Enumeration (https://www.w3.org/TR/webauthn/#enum-userVerificationRequirement)
    enum class UserVerificationRequirementType {

        // Required User verification is required to create/release a credential
        Required,

        // Preferred User verification is preferred to create/release a credential
        Preferred, // This is the default

        // Discouraged The authenticator should not verify the user for the credential
        Discouraged,

        // Invalid value
        Invalid = -1
    };

    // map UserVerificationRequirementType values to JSON as strings
    NLOHMANN_JSON_SERIALIZE_ENUM(UserVerificationRequirementType, {
        { UserVerificationRequirementType::Invalid,           nullptr },
        { UserVerificationRequirementType::Invalid,                "" },
        { UserVerificationRequirementType::Required,       "required" },
        { UserVerificationRequirementType::Preferred,     "preferred" },
        { UserVerificationRequirementType::Discouraged, "discouraged" }
    })

    // AuthenticatorFlagsType A byte of information returned during during ceremonies in the
    // authenticatorData that contains bits that give us information about the
    // whether the user was present and/or verified during authentication, and whether
    // there is attestation or extension data present. Bit 0 is the least significant bit.
    //
    // Specification: §6.1. Authenticator Data - Flags (https://www.w3.org/TR/webauthn/#flags)
    enum class AuthenticatorFlagsType : uint8_t {

        // The bits that do not have flags are reserved for future use.

        // UserPresent Bit 00000001 in the byte sequence. Tells us if user is present. Also referred to as the UP flag.
        UserPresent = static_cast<uint8_t>(1U), // Referred to as UP

        // RFU1 is a reserved for future use flag.
        RFU1 = static_cast<uint8_t>(1U << 1),

        // UserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
        // by the authenticator using a biometric or PIN. Also referred to as the UV flag.
        UserVerified = static_cast<uint8_t>(1U << 2),

        // BackupEligible Bit 00001000 in the byte sequence. Tells us if a backup is eligible for device. Also referred
        // to as the BE flag.
        BackupEligible = static_cast<uint8_t>(1U << 3), // Referred to as BE

        // BackupState Bit 00010000 in the byte sequence. Tells us if a backup state for device. Also referred to as the
        // BS flag.
        BackupState = static_cast<uint8_t>(1U << 4),

        // RFU2 is a reserved for future use flag.
        RFU2 = static_cast<uint8_t>(1U << 5),

        // AttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether
        // the authenticator added attested credential data. Also referred to as the AT flag.
        AttestedCredentialData = static_cast<uint8_t>(1U << 6),

        // HasExtensions Bit 10000000 in the byte sequence. Indicates if the authenticator data has extensions. Also
        // referred to as the ED flag.
        HasExtensions = static_cast<uint8_t>(1U << 7)
    };

    inline constexpr enum AuthenticatorFlagsType operator |(const enum AuthenticatorFlagsType selfValue, const enum AuthenticatorFlagsType inValue) noexcept {

        return static_cast<enum AuthenticatorFlagsType>(static_cast<uint8_t>(selfValue) | static_cast<uint8_t>(inValue));
    }

    inline constexpr enum AuthenticatorFlagsType operator &(const enum AuthenticatorFlagsType selfValue, const enum AuthenticatorFlagsType inValue) noexcept {

        return static_cast<enum AuthenticatorFlagsType>(static_cast<uint8_t>(selfValue) & static_cast<uint8_t>(inValue));
    }

    inline enum AuthenticatorFlagsType& operator |=(enum AuthenticatorFlagsType& selfValue, const enum AuthenticatorFlagsType inValue) noexcept {

        return reinterpret_cast<enum AuthenticatorFlagsType&>(reinterpret_cast<uint8_t&>(selfValue) |= static_cast<uint8_t>(inValue));
    }

    inline enum AuthenticatorFlagsType& operator &=(enum AuthenticatorFlagsType& selfValue, const enum AuthenticatorFlagsType inValue) noexcept {

        return reinterpret_cast<enum AuthenticatorFlagsType&>(reinterpret_cast<uint8_t&>(selfValue) &= static_cast<uint8_t>(inValue));
    }

    inline void from_json(const json& j, AuthenticatorFlagsType& authenticatorFlags) {

        auto value = j.get<uint8_t>();
        authenticatorFlags = static_cast<AuthenticatorFlagsType>(static_cast<uint8_t>(0U));

        if (value & static_cast<uint8_t>(1U)) {
            authenticatorFlags = AuthenticatorFlagsType::UserPresent;
        }

        if (value & static_cast<uint8_t>(1U << 1)) {
            authenticatorFlags |= AuthenticatorFlagsType::RFU1;
        }

        if (value & static_cast<uint8_t>(1U << 2)) {
            authenticatorFlags |= AuthenticatorFlagsType::UserVerified;
        }

        if (value & static_cast<uint8_t>(1U << 3)) {
            authenticatorFlags |= AuthenticatorFlagsType::BackupEligible;
        }

        if (value & static_cast<uint8_t>(1U << 4)) {
            authenticatorFlags |= AuthenticatorFlagsType::BackupState;
        }

        if (value & static_cast<uint8_t>(1U << 5)) {
            authenticatorFlags |= AuthenticatorFlagsType::RFU2;
        }

        if (value & static_cast<uint8_t>(1U << 6)) {
            authenticatorFlags |= AuthenticatorFlagsType::AttestedCredentialData;
        }

        if (value & static_cast<uint8_t>(1U << 7)) {
            authenticatorFlags |= AuthenticatorFlagsType::HasExtensions;
        }
    }

    inline void to_json(json& j, const AuthenticatorFlagsType authenticatorFlags) {

        j = json{
            static_cast<uint8_t>(authenticatorFlags)
        };
    }

    inline bool HasUserPresent(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::UserPresent) != 0;
    }

    inline bool HasRFU1(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::RFU1) != 0;
    }

    inline bool HasUserVerified(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::UserVerified) != 0;
    }

    inline bool HasBackupEligible(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::BackupEligible) != 0;
    }

    inline bool HasBackupState(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::BackupState) != 0;
    }

    inline bool HasRFU2(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::RFU2) != 0;
    }

    inline bool HasAttestedCredentialData(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::AttestedCredentialData) != 0;
    }

    inline bool HasExtensions(const AuthenticatorFlagsType authenticatorFlags) noexcept {

        return static_cast<uint8_t>(authenticatorFlags & AuthenticatorFlagsType::HasExtensions) != 0;
    }

    // Structs

    struct AttestedCredentialDataType {

        AttestedCredentialDataType() noexcept = default;

        AttestedCredentialDataType(const json& j) :
            AAGUID(j["aaguid"].get<std::vector<uint8_t>>()),
            CredentialID(j["credential_id"].get<std::vector<uint8_t>>()),
            CredentialPublicKey(j["public_key"].get<std::vector<uint8_t>>()) {
        }

        AttestedCredentialDataType(const AttestedCredentialDataType& attestedCredentialData) noexcept = default;
        AttestedCredentialDataType(AttestedCredentialDataType&& attestedCredentialData) noexcept = default;
        ~AttestedCredentialDataType() noexcept = default;

        AttestedCredentialDataType& operator =(const AttestedCredentialDataType& other) noexcept = default;
        AttestedCredentialDataType& operator =(AttestedCredentialDataType&& other) noexcept = default;

        std::vector<uint8_t> AAGUID;
        std::vector<uint8_t> CredentialID;

        // The raw credential public key bytes received from the attestation data.
        std::vector<uint8_t> CredentialPublicKey;
    };

    inline void to_json(json& j, const AttestedCredentialDataType& attestedCredentialData) {

        j = json{
            { "aaguid",                  attestedCredentialData.AAGUID },
            { "credential_id",     attestedCredentialData.CredentialID },
            { "public_key", attestedCredentialData.CredentialPublicKey }
        };
    }

    inline void from_json(const json& j, AttestedCredentialDataType& attestedCredentialData) {

        j.at("aaguid").get_to(attestedCredentialData.AAGUID);
        j.at("credential_id").get_to(attestedCredentialData.CredentialID);
        j.at("public_key").get_to(attestedCredentialData.CredentialPublicKey);
    }

    // AuthenticatorResponseType represents the IDL with the same name.
    //
    // Authenticators respond to Relying Party requests by returning an object derived from the AuthenticatorResponse
    // interface
    //
    // Specification: §5.2. Authenticator Responses (https://www.w3.org/TR/webauthn/#iface-authenticatorresponse)
    struct AuthenticatorResponseType {

        AuthenticatorResponseType() noexcept = default;

        AuthenticatorResponseType(const json& j) :
            ClientDataJSON(j["clientDataJSON"].get<URLEncodedBase64Type>()) {
        }

        AuthenticatorResponseType(const AuthenticatorResponseType& authenticatorResponse) noexcept = default;
        AuthenticatorResponseType(AuthenticatorResponseType&& authenticatorResponse) noexcept = default;
        virtual ~AuthenticatorResponseType() noexcept = default;

        AuthenticatorResponseType& operator =(const AuthenticatorResponseType& other) noexcept = default;
        AuthenticatorResponseType& operator =(AuthenticatorResponseType&& other) noexcept = default;

        // From the spec https://www.w3.org/TR/webauthn/#dom-authenticatorresponse-clientdatajson
        // This attribute contains a JSON serialization of the client data passed to the authenticator
        // by the client in its call to either create() or get().
        URLEncodedBase64Type ClientDataJSON;
    };

    inline void to_json(json& j, const AuthenticatorResponseType& authenticatorResponse) {

        j = json{
            { "clientDataJSON", authenticatorResponse.ClientDataJSON }
        };
    }

    inline void from_json(const json& j, AuthenticatorResponseType& authenticatorResponse) {

        j.at("clientDataJSON").get_to(authenticatorResponse.ClientDataJSON);
    }

    // AuthenticatorDataType represents the IDL with the same name.
    //
    // The authenticator data structure encodes contextual bindings made by the authenticator. These bindings are controlled
    // by the authenticator itself, and derive their trust from the WebAuthn Relying Party's assessment of the security
    // properties of the authenticator. In one extreme case, the authenticator may be embedded in the client, and its
    // bindings may be no more trustworthy than the client data. At the other extreme, the authenticator may be a discrete
    // entity with high-security hardware and software, connected to the client over a secure channel. In both cases, the
    // Relying Party receives the authenticator data in the same format, and uses its knowledge of the authenticator to make
    // trust decisions.
    //
    // The authenticator data has a compact but extensible encoding. This is desired since authenticators can be devices
    // with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
    //
    // Specification: §6.1. Authenticator Data (https://www.w3.org/TR/webauthn/#sctn-authenticator-data)
    struct AuthenticatorDataType {

        AuthenticatorDataType() noexcept = default;

        AuthenticatorDataType(const json& j) :
            RPIDHash(j["rpid"].get<std::vector<uint8_t>>()),
            Flags(j["flags"].get<AuthenticatorFlagsType>()),
            Counter(j["sign_count"].get<uint32_t>()),
            AttData(j["att_data"].get<AttestedCredentialDataType>()),
            ExtData(j["ext_data"].get<std::vector<uint8_t>>()) {
        }

        AuthenticatorDataType(const AuthenticatorDataType& authenticatorData) noexcept = default;
        AuthenticatorDataType(AuthenticatorDataType&& authenticatorData) noexcept = default;
        ~AuthenticatorDataType() noexcept = default;

        AuthenticatorDataType& operator =(const AuthenticatorDataType& other) noexcept = default;
        AuthenticatorDataType& operator =(AuthenticatorDataType&& other) noexcept = default;

        // Unmarshal will take the raw Authenticator Data and marshals it into AuthenticatorDataType for further validation.
        // The authenticator data has a compact but extensible encoding. This is desired since authenticators can be
        // devices with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
        // The authenticator data structure is a byte array of 37 bytes or more, and is laid out in this table:
        // https://www.w3.org/TR/webauthn/#table-authData
        inline std::optional<ErrorType> Unmarshal(const std::vector<uint8_t>& rawAuthData) noexcept {

            if (MIN_AUTH_DATA_LENGTH > rawAuthData.size()) {
                return ErrBadRequest().WithDetails("Authenticator data length too short")
                                      .WithInfo(fmt::format("Expected data greater than {} bytes. Got {} bytes", MIN_AUTH_DATA_LENGTH, rawAuthData.size()));
            }

            RPIDHash = std::vector<uint8_t>(rawAuthData.cbegin(), rawAuthData.cbegin() + 32);
            Flags = AuthenticatorFlagsType(rawAuthData[32]);
            Counter = MAKE_UINT32(rawAuthData[33], rawAuthData[34], rawAuthData[35], rawAuthData[36]);

            auto remaining = rawAuthData.size() - MIN_AUTH_DATA_LENGTH;

            if (HasAttestedCredentialData(Flags)) {

                if (rawAuthData.size() > MIN_ATTESTED_AUTH_LENGTH) {

                    auto err = _UnmarshalAttestedData(rawAuthData);
                    if (err) {
                        return err;
                    }

                    auto attDataLen = AttData.AAGUID.size() + 2 + AttData.CredentialID.size() + AttData.CredentialPublicKey.size();
                    remaining = remaining - attDataLen;
                } else {
                    return ErrBadRequest().WithDetails("Attested credential flag set but data is missing");
                }
            } else {

                if (!HasExtensions(Flags) && rawAuthData.size() != 37) {
                    return ErrBadRequest().WithDetails("Attested credential flag not set");
                }
            }

            if (HasExtensions(Flags)) {

                if (remaining != 0) {

                    ExtData = std::vector<uint8_t>(rawAuthData.cend() - remaining, rawAuthData.cend());
                    remaining -= ExtData.size();
                } else {
                    return ErrBadRequest().WithDetails("Extensions flag set but extensions data is missing");
                }
            }

            if (remaining != 0) {
                return ErrBadRequest().WithDetails("Leftover bytes decoding AuthenticatorData");
            }

            return std::nullopt;
        }

        // Verify on AuthenticatorData handles Steps 9 through 12 for Registration
        // and Steps 11 through 14 for Assertion.
        inline std::optional<ErrorType>
        Verify(const std::vector<uint8_t>& rpIdHash, 
               const std::vector<uint8_t>& appIDHash, 
               bool userVerificationRequired) const noexcept {

            // Registration Step 9 & Assertion Step 11
            // Verify that the RP ID hash in authData is indeed the SHA-256
            // hash of the RP ID expected by the RP.
            if (RPIDHash != rpIdHash && RPIDHash != appIDHash) {
                return ErrVerification().WithInfo(fmt::format("RP Hash mismatch. Expected {} and Received {}",
                                                              fmt::join(RPIDHash, ", "),
                                                              fmt::join(rpIdHash, ", ")));
            }

            // Registration Step 10 & Assertion Step 12
            // Verify that the User Present bit of the flags in authData is set.
            if (!HasUserPresent(Flags)) {
                return ErrVerification().WithInfo("User presence flag not set by authenticator");
            }

            // Registration Step 11 & Assertion Step 13
            // If user verification is required for this assertion, verify that
            // the User Verified bit of the flags in authData is set.
            if (userVerificationRequired && !HasUserVerified(Flags)) {
                return ErrVerification().WithInfo("User verification required but flag not set by authenticator");
            }

            // Registration Step 12 & Assertion Step 14
            // Verify that the values of the client extension outputs in clientExtensionResults
            // and the authenticator extension outputs in the extensions in authData are as
            // expected, considering the client extension input values that were given as the
            // extensions option in the create() call. In particular, any extension identifier
            // values in the clientExtensionResults and the extensions in authData MUST be also be
            // present as extension identifier values in the extensions member of options, i.e., no
            // extensions are present that were not requested. In the general case, the meaning
            // of "are as expected" is specific to the Relying Party and which extensions are in use.

            // This is not yet fully implemented by the spec or by browsers.

            return std::nullopt;
        }

        std::vector<uint8_t> RPIDHash;
        AuthenticatorFlagsType Flags;
        uint32_t Counter;
        AttestedCredentialDataType AttData;
        std::vector<uint8_t> ExtData;

    private:
        // If Attestation Data is present, unmarshall that into the appropriate public key structure.
        inline std::optional<ErrorType>
        _UnmarshalAttestedData(const std::vector<uint8_t>& rawAuthData) noexcept {

            AttData.AAGUID = std::vector<uint8_t>(rawAuthData.cbegin() + 37, rawAuthData.cbegin() + 53);

            auto idLength = MAKE_UINT16(rawAuthData[53], rawAuthData[54]);
            
            if (rawAuthData.size() < static_cast<size_t>(MIN_ATTESTED_AUTH_LENGTH + idLength)) {
                return ErrBadRequest().WithDetails("Authenticator attestation data length too short");
            }

            if (idLength > MAX_CREDENTIAL_ID_LENGTH) {
                return ErrBadRequest().WithDetails("Authenticator attestation data credential id length too long");
            }

            AttData.CredentialID = std::vector<uint8_t>(rawAuthData.cbegin() + MIN_ATTESTED_AUTH_LENGTH, rawAuthData.cbegin() + MIN_ATTESTED_AUTH_LENGTH + idLength);
            auto lastChunk = std::vector<uint8_t>(rawAuthData.cbegin() + MIN_ATTESTED_AUTH_LENGTH + idLength, rawAuthData.cend());

            auto data = _UnmarshalCredentialPublicKey(lastChunk);
            if (!data) {
                return ErrBadRequest().WithDetails(fmt::format("Could not unmarshal Credential Public Key: {}", std::string(data.error())));
            }
            AttData.CredentialPublicKey = data.value();

            return std::nullopt;
        }

        // Unmarshall the credential's Public Key into CBOR encoding.
        inline static expected<std::vector<uint8_t>> _UnmarshalCredentialPublicKey(const std::vector<uint8_t>& keyBytes) noexcept {

            return WebAuthNCBOR::Remarshal(keyBytes);
        }
    };

    inline void to_json(json& j, const AuthenticatorDataType& authenticatorData) {

        j = json{
            { "rpid",      authenticatorData.RPIDHash },
            { "flags",        authenticatorData.Flags },
            { "sign_count", authenticatorData.Counter },
            { "att_data",   authenticatorData.AttData },
            { "ext_data",   authenticatorData.ExtData }
        };
    }

    inline void from_json(const json& j, AuthenticatorDataType& authenticatorData) {

        j.at("rpid").get_to(authenticatorData.RPIDHash);
        j.at("flags").get_to(authenticatorData.Flags);
        j.at("sign_count").get_to(authenticatorData.Counter);
        j.at("att_data").get_to(authenticatorData.AttData);
        j.at("ext_data").get_to(authenticatorData.ExtData);
    }

    // Functions

    // ResidentKeyRequired - Require that the key be private key resident to the client device.
    inline bool ResidentKeyRequired() noexcept {

        return true;
    }

    // ResidentKeyNotRequired - Do not require that the private key be resident to the client device.
    inline bool ResidentKeyNotRequired() noexcept {

        return false;
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_AUTHENTICATOR_IPP */
