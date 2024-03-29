//
//  Authenticator.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_AUTHENTICATOR_IPP
#define WEBAUTHN_WEBAUTHN_AUTHENTICATOR_IPP

#include "../Protocol/Options.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    using json = nlohmann::json;

    struct AuthenticatorType {

        // UpdateCounter updates the authenticator and either sets the clone warning value or the sign count.
        //
        // Step 17 of §7.2. about verifying attestation. If the signature counter value authData.signCount
        // is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then
        // run the following sub-step:
        //
        // If the signature counter value authData.signCount is
        //
        // Greater than the signature counter value stored in conjunction with credential’s id attribute.
        // Update the stored signature counter value, associated with credential’s id attribute, to be the value of
        // authData.signCount.
        //
        // Less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
        // This is a signal that the authenticator may be cloned, see CloneWarning above for more information.
        inline void UpdateCounter(const uint32_t authDataCount) noexcept {

            if ((!(authDataCount > SignCount)) && (authDataCount != 0 || SignCount != 0)) {

                CloneWarning = true;
                return;
            }

            SignCount = authDataCount;
        }

        // The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
        // identifier of the authenticator model being sought.
        std::vector<uint8_t> AAGUID;
        // SignCount -Upon a new login operation, the Relying Party compares the stored signature counter value
        // with the new signCount value returned in the assertion’s authenticator data. If this new
        // signCount value is less than or equal to the stored value, a cloned authenticator may
        // exist, or the authenticator may be malfunctioning.
        uint32_t SignCount{0};
        // CloneWarning - This is a signal that the authenticator may be cloned, i.e. at least two copies of the
        // credential private key may exist and are being used in parallel. Relying Parties should incorporate
        // this information into their risk scoring. Whether the Relying Party updates the stored signature
        // counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.
        bool CloneWarning{false};

        // Attachment is the authenticatorAttachment value returned by the request.
        std::optional<Protocol::AuthenticatorAttachmentType> Attachment;
    };

    // SelectAuthenticator allow for easy marshaling of authenticator options that are provided to the user.
    inline Protocol::AuthenticatorSelectionType SelectAuthenticator(const std::string& att, const bool rrk, const std::string& uv) {

        return Protocol::AuthenticatorSelectionType{
            json(att).get<Protocol::AuthenticatorAttachmentType>(),
            rrk,
            std::nullopt,
            json(uv).get<Protocol::UserVerificationRequirementType>()
        };
    }
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_AUTHENTICATOR_IPP */
