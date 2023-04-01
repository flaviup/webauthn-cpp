//
//  IUser.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_IUSER_HPP
#define WEBAUTHN_WEBAUTHN_IUSER_HPP

#include <string>
#include <vector>
#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    // IUser is am interface with the Relying Party's User entry and provides the fields and methods needed for WebAuthN
    // registration operations.
    struct IUser {

        IUser() noexcept = default;
        IUser(const IUser& user) noexcept = default;
        IUser(IUser&& user) noexcept = default;
        virtual ~IUser() noexcept = default;

        IUser& operator =(const IUser& other) noexcept = default;
        IUser& operator =(IUser&& other) noexcept = default;

        // GetWebAuthNID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
        // size of 64 bytes, and is not meant to be displayed to the user.
        //
        // To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
        // member, not the displayName nor name members. See Section 6.1 of [RFC8266].
        //
        // It's recommended this value is completely random and uses the entire 64 bytes.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
        virtual std::vector<uint8_t> GetWebAuthNID() const noexcept = 0;

        // GetWebAuthNName provides the name attribute of the user account during registration and is a human-palatable name for the user
        // account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
        // choose this, and SHOULD NOT restrict the choice more than necessary.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
        virtual std::string GetWebAuthNName() const noexcept = 0;

        // GetWebAuthNDisplayName provides the name attribute of the user account during registration and is a human-palatable
        // name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
        // SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
        virtual std::string GetWebAuthNDisplayName() const noexcept = 0;

        // GetWebAuthNCredentials provides the list of Credential objects owned by the user.
        virtual std::vector<CredentialType> GetWebAuthNCredentials() const noexcept = 0;

        // GetWebAuthNIcon is a deprecated option.
        // Deprecated: this has been removed from the specification recommendation. Suggest a blank string.
        virtual std::string GetWebAuthNIcon() const noexcept = 0;
    };
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_IUSER_HPP */
