//
//  Credential.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_CREDENTIAL_IPP
#define WEBAUTHN_WEBAUTHN_CREDENTIAL_IPP

#include "Authenticator.ipp"
#include "../Protocol/Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    using json = nlohmann::json;

    struct CredentialFlagsType {

        CredentialFlagsType() noexcept = default;

        // Flag UP indicates the users presence.
        bool UserPresent;
        // Flag UV indicates the user performed verification.
        bool UserVerified;
        // Flag BE indicates the credential is able to be backed up and/or sync'd between devices. This should NEVER change.
        bool BackupEligible;
        // Flag BS indicates the credential has been backed up and/or sync'd. This value can change but it's recommended
        // that RP's keep track of this value.
        bool BackupState;
    };

    // CredentialType contains all needed information about a WebAuthn credential for storage.
    struct CredentialType {

        CredentialType() noexcept = default;

        // Descriptor converts the CredentialType into a Protocol::CredentialDescriptorType.
        inline Protocol::CredentialDescriptorType ToDescriptorType() const noexcept {

            Protocol::URLEncodedBase64Type credentialID;
            credentialID.reserve(this->ID.size());
            for (int value : this->ID) credentialID += std::to_string(value);

            Protocol::CredentialDescriptorType cdt;
            cdt.Type = Protocol::PublicKeyCredentialType();
            cdt.CredentialID = credentialID;
            cdt.Transports = this->Transports;
            cdt.AttestationType = this->AttestationType;

            return cdt;
        }
    
        // A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
        std::vector<uint8_t> ID;
        // The public key portion of a Relying Party-specific credential key pair, generated by an authenticator and returned to
        // a Relying Party at registration time (see also public key credential). The private key portion of the credential key
        // pair is known as the credential private key. Note that in the case of self attestation, the credential key pair is also
        // used as the attestation key pair, see self attestation for details.
        std::vector<uint8_t> PublicKey;
        // The attestation format used (if any) by the authenticator when creating the credential.
        std::string AttestationType;
        // The transport types the authenticator supports.
        std::vector<Protocol::AuthenticatorTransportType> Transports;
        // The commonly stored flags.
        CredentialFlagsType Flags;
        // The Authenticator information for a given certificate.
        AuthenticatorType Authenticator;
    };

    // MakeNewCredential will return a credential pointer on successful validation of a registration response.
    inline expected<CredentialType> MakeNewCredential(const Protocol::ParsedCredentialCreationDataType& c) noexcept {

        auto newCredential = CredentialType{
            ID:              c.Response.AttestationObject.AuthData.AttData.CredentialID,
            PublicKey:       c.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
            AttestationType: c.Response.AttestationObject.Format,
            Transports:      c.Response.Transports,
            Flags: CredentialFlagsType{
                UserPresent:    Protocol::HasUserPresent(c.Response.AttestationObject.AuthData.Flags),
                UserVerified:   Protocol::HasUserVerified(c.Response.AttestationObject.AuthData.Flags),
                BackupEligible: Protocol::HasBackupEligible(c.Response.AttestationObject.AuthData.Flags),
                BackupState:    Protocol::HasBackupState(c.Response.AttestationObject.AuthData.Flags)
            },
            Authenticator: AuthenticatorType{
                AAGUID:     c.Response.AttestationObject.AuthData.AttData.AAGUID,
                SignCount:  c.Response.AttestationObject.AuthData.Counter,
                Attachment: c.AuthenticatorAttachment
            }
        };

        return newCredential;
    }
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_CREDENTIAL_IPP */