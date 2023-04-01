# webauthn-cpp
WebAuthN/FIDO2 Relying Party (server side) C++ implementation library.

Based on [this](https://github.com/go-webauthn/webauthn) Go implementation.

Currently there is no testing code and overall it hasn't been tested thoroughly.

In order to build the library you need to have premake5 installed. You also need to have the dependencies specified in premake5.lua script installed on your system.

To build as static library:
```
premake5 --os=macosx gmake2 &&
make config=staticlib-release  
```

To build as shared library:

```
premake5 --os=macosx gmake2 &&
MACOSX_DEPLOYMENT_TARGET=12.6 make config=sharedlib-release  
```

To generate the XCode workspace:

```
premake5 --os=macosx xcode4
```

Usage example:

```
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <string>
#include "../webauthn-cpp/WebAuthN.hpp"

using json = nlohmann::json;

WebAuthN::WebAuthN::CredentialType* RegisteredCredential = nullptr;

// You need to implement an IUser service

struct DefaultUser : public WebAuthN::WebAuthN::IUser {

    DefaultUser() noexcept = default;
    DefaultUser(const DefaultUser& defaultUser) noexcept = default;
    DefaultUser(DefaultUser&& defaultUser) noexcept = default;
    ~DefaultUser() noexcept override = default;

    DefaultUser& operator =(const DefaultUser& other) noexcept = default;
    DefaultUser& operator =(DefaultUser&& other) noexcept = default;

    // GetWebAuthNID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
    // size of 64 bytes, and is not meant to be displayed to the user.
    //
    // To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
    // member, not the displayName nor name members. See Section 6.1 of [RFC8266].
    //
    // It's recommended this value is completely random and uses the entire 64 bytes.
    //
    // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
    std::vector<uint8_t> GetWebAuthNID() const noexcept override {
      return Id;
    }

    // GetWebAuthNName provides the name attribute of the user account during registration and is a human-palatable name for the user
    // account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
    // choose this, and SHOULD NOT restrict the choice more than necessary.
    //
    // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
    std::string GetWebAuthNName() const noexcept override {
        return "defaultUser";
    }

    // GetWebAuthNDisplayName provides the name attribute of the user account during registration and is a human-palatable
    // name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
    // SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
    //
    // Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
    std::string GetWebAuthNDisplayName() const noexcept override {
      return "Default User";
    }

    // GetWebAuthNCredentials provides the list of Credential objects owned by the user.
    std::vector<WebAuthN::WebAuthN::CredentialType> GetWebAuthNCredentials() const noexcept override {
      return (RegisteredCredential == nullptr) ? std::vector<WebAuthN::WebAuthN::CredentialType>{} : std::vector<WebAuthN::WebAuthN::CredentialType>{ *RegisteredCredential };
    };

    // GetWebAuthNIcon is a deprecated option.
    // Deprecated: this has been removed from the specification recommendation. Suggest a blank string.
    std::string GetWebAuthNIcon() const noexcept override {
      return "https://pics.com/avatar.png";
    };
  
    std::vector<uint8_t> Id{ 0xb0, 0xaf, 0x23, 0x18, 0xe5, 0x07, 0x3e, 0x7c, 0x8c, 0xc7, 0xd7, 0xba, 0xa4, 0x1e, 0x71, 0xb9,
      0x63, 0x09, 0xf3, 0x48, 0x1c, 0x69, 0xbf, 0x5d, 0x8a, 0x8c, 0x5b, 0x36, 0xe2, 0xda, 0x8a, 0x0d };
};

// useful for step debugging by loading the client responses from a text file

std::string loadTextFromFile(const std::string& filePath) {
    
    std::stringstream buffer;
    std::ifstream f(filePath);
    buffer << f.rdbuf();
    return buffer.str();
}

// test program main function

int main(int argc, const char * argv[]) {

    // Configuration object
    /*WebAuthN::WebAuthN::ConfigType cfg{
        .RPID = "northern-subsequent-stock.glitch.me", //"github.github.com", // change this
        .RPDisplayName = "testweb",
        .RPOrigins = { "https://northern-subsequent-stock.glitch.me", "android:apk-key-hash:" }, //{ "https://github.github.com" }, // change this
        .Debug = true,
        .AttestationPreference = WebAuthN::Protocol::ConveyancePreferenceType::IndirectAttestation
    };*/
    /*WebAuthN::WebAuthN::ConfigType cfg{
        .RPID = "successful-foil-olive.glitch.me", //"github.github.com", // change this
        .RPDisplayName = "testweb",
        .RPOrigins = { "https://successful-foil-olive.glitch.me", "android:apk-key-hash:" }, //{ "https://github.github.com" }, // change this
        .Debug = true,
        .AttestationPreference = WebAuthN::Protocol::ConveyancePreferenceType::IndirectAttestation
    };*/
    WebAuthN::WebAuthN::ConfigType cfg{
        .RPID = "github.github.com", // change this
        .RPDisplayName = "testweb",
        .RPOrigins = { "https://github.github.com" }, // change this
        .Debug = true,
        .AttestationPreference = WebAuthN::Protocol::ConveyancePreferenceType::IndirectAttestation
    };

    // Create WebAuthN object
    auto result = GetWebAuthN(cfg);

    if (!result) {

      std::cerr << std::string(result.error()) << std::endl;
      return -1;
    }
    auto& wt = result.value();
    DefaultUser du{};
    const WebAuthN::WebAuthN::WebAuthNType::RegistrationOptionHandlerType registrationOptions[]{ WebAuthN::WebAuthN::WebAuthNType::WithConveyancePreference(WebAuthN::Protocol::ConveyancePreferenceType::DirectAttestation),
        WebAuthN::WebAuthN::WebAuthNType::WithAuthenticatorSelection(
            WebAuthN::Protocol::AuthenticatorSelectionType(WebAuthN::Protocol::AuthenticatorAttachmentType::Platform,
                                                           true,
                                                           std::nullopt,
                                                           WebAuthN::Protocol::UserVerificationRequirementType::Required))
    };

    // Begin Registration (Attestation)
    auto beginRegistration = wt.BeginRegistration(du, registrationOptions);//WebAuthN::WebAuthN::WebAuthNType::DEFAULT_REGISTRATION_OPTIONS);

    if (!beginRegistration) {

      std::cerr << std::string(beginRegistration.error()) << std::endl;
      return -1;
    }
    auto [credentialCreation, sessionData] = beginRegistration.value();

    std::cout << json(credentialCreation).dump() << std::endl;

    // End Registration: load client response here from file; set a breakpoint here before continuing
    std::string clientRegistrationResponse = loadTextFromFile("clientjson.txt");
    auto finishRegistration = wt.FinishRegistration(du, sessionData, clientRegistrationResponse);

    if (!finishRegistration) {

      std::cerr << std::string(finishRegistration.error()) << std::endl;
      return -1;
    }
    auto registration = finishRegistration.value();

    std::cout << "REGISTRATION SUCCESS" << std::endl;

    RegisteredCredential = &registration;
    
    //std::clog << std::endl << "FIDO EC P256: " << WebAuthN::Protocol::WebAuthNCBOR::VectorUint8ToHexString(registration.PublicKey);
    
    const WebAuthN::WebAuthN::WebAuthNType::LoginOptionHandlerType loginOptions[]{
        WebAuthN::WebAuthN::WebAuthNType::WithUserVerification(WebAuthN::Protocol::UserVerificationRequirementType::Required)
    };
    
    // Begin Login/Authentication (Assertion)
    auto beginLogin = wt.BeginLogin(du, loginOptions); //WebAuthN::WebAuthN::WebAuthNType::DEFAULT_LOGIN_OPTIONS);
    
    if (!beginLogin) {

      std::cerr << std::string(beginLogin.error()) << std::endl;
      return -1;
    }
    
    auto [credentialAssertion, sessionDataLogin] = beginLogin.value();

    std::cout << json(credentialAssertion).dump() << std::endl;

    // End Login: load client response here from file; set a breakpoint here before continuing
    std::string clientLoginResponse = loadTextFromFile("clientjson.txt");
    auto finishLogin = wt.FinishLogin(du, sessionDataLogin, clientLoginResponse);

    if (!finishLogin) {

      std::cerr << std::string(finishLogin.error()) << std::endl;
      return -1;
    }
    auto login = finishLogin.value();

    std::cout << "LOGIN SUCCESS" << std::endl;

    return 0;
}
```
