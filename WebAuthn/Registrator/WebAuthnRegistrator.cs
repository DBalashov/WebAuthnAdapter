using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace WebAuthn;

/// <summary> Register user with webauthn </summary>
sealed class WebAuthnRegistrator : RegistratorAuthenticatorBase, IWebAuthnRegistrator
{
    const string CLIENT_DATA_TYPE = "webauthn.create";

    public WebAuthnRegistrator(WebAuthnSettings settings, IWebAuthnUserFactory userFactory) : base(settings, userFactory)
    {
    }
    
    public string GetScript(string callbackUrl, string callbackFunctionSuccessName, string callbackFunctionFailedName, string userName) =>
        @$"
var publicKey = WebAuthnRegBuildPublicKey('{Convert.ToBase64String(Settings.Challenge)}', '{Settings.RelyingPartyId}', '{userName}');
WebAuthnCallRegistration(publicKey, '{callbackUrl}', {callbackFunctionSuccessName},{callbackFunctionFailedName});";

    public WebAuthnResult Register(WebAuthnRegisterParams parms, out IWebAuthnUser outUser)
    {
        outUser = null!;
        try
        {
            if (parms.ClientData is not {Type: CLIENT_DATA_TYPE})
                return WebAuthnResult.IncorrectClientData;

            if (parms.ClientData.Challenge == null || !Settings.Challenge.SequenceEqual(parms.ClientData.Challenge))
                return WebAuthnResult.IncorrectChallenge;

            if (string.Compare(parms.ClientData.Origin, Settings.Origin, StringComparison.InvariantCultureIgnoreCase) != 0)
                return WebAuthnResult.IncorrectOrigin;

            if (parms.AttestationObject == null)
                return WebAuthnResult.IncorrectClientData;

            var attestation = new WebAuthnAttestation(parms.AttestationObject);

            // Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
            var computedRpIdHash = Hasher.ComputeHash(Encoding.UTF8.GetBytes(Settings.RelyingPartyId));
            if (!attestation.RelayPartyIdHash.SequenceEqual(computedRpIdHash))
                return WebAuthnResult.IncorrectRelayPartyId;

            if (!attestation.Flags.HasFlag(WebAuthnFlags.UserVerified))
                return WebAuthnResult.UserEmpty;

            if (!attestation.Flags.HasFlag(WebAuthnFlags.UserPresent))
                return WebAuthnResult.UserNotPresent;

            // Check that the credentialId is not yet registered to any other user
            if (UserFactory.Get(attestation.CredentialId) != null)
                return WebAuthnResult.DuplicateCredential;

            outUser = new WebAuthnRegistratorResult(parms.UserName,
                                                    attestation.CredentialId,
                                                    attestation.PublicKey,
                                                    attestation.Counter);
            return WebAuthnResult.OK;
        }
        catch (Exception e)
        {
            Debug.WriteLine("TryProcess: " + (e.InnerException ?? e).Message, "WebAuthnRegistrator");
            return WebAuthnResult.IncorrectClientData;
        }
    }
}