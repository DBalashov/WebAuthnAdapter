using System.Security.Cryptography;

namespace WebAuthn;

abstract class RegistratorAuthenticatorBase
{
    protected readonly WebAuthnSettings     Settings;
    protected readonly IWebAuthnUserFactory UserFactory;
    protected readonly SHA256               Hasher = SHA256.Create();

    protected RegistratorAuthenticatorBase(WebAuthnSettings settings, IWebAuthnUserFactory userFactory)
    {
        Settings    = settings;
        UserFactory = userFactory;
    }

#if DEBUG
    public override string ToString() => Settings.RelyingPartyId + ", " + Settings.Challenge;
#endif
}