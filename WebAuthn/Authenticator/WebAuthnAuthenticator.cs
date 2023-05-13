using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WebAuthn;

/// <summary> Authenticate user with webauthn </summary>
sealed class WebAuthnAuthenticator : RegistratorAuthenticatorBase, IWebAuthnAuthenticator
{
    const string CLIENT_DATA_TYPE = "webauthn.get";

    public WebAuthnAuthenticator(WebAuthnSettings settings, IWebAuthnUserFactory userFactory) : base(settings, userFactory)
    {
    }
    
    public string GetScript(string callbackUrl, string callbackFunctionSuccessName, string callbackFunctionFailedName, IWebAuthnUser user) =>
        @$"
var publicKey = WebAuthnAuthBuildPublicKey('{Convert.ToBase64String(Settings.Challenge)}', '{Settings.RelyingPartyId}', '{Convert.ToBase64String(user.CredentialId)}');
WebAuthnCallAuthentication(publicKey, '{user.UserName}', '{callbackUrl}', {callbackFunctionSuccessName}, {callbackFunctionFailedName});";

    public WebAuthnResult Authenticate(WebAuthnAuthenticateParams parms)
    {
        if (string.IsNullOrEmpty(parms.UserName))
            return WebAuthnResult.IncorrentUserName;

        var user = UserFactory.Get(parms.CredentialId);
        if (user == null)
            return WebAuthnResult.UserNotFound;

        if (!user.CredentialId.SequenceEqual(parms.CredentialId))
            return WebAuthnResult.IncorrectKey;

        if (parms.UserName != user.UserName)
            return WebAuthnResult.IncorrentUserName;

        var clientData = JsonSerializer.Deserialize<WebAuthnClientData>(Encoding.UTF8.GetString(parms.ClientData));
        if (clientData is not {Type: CLIENT_DATA_TYPE})
            return WebAuthnResult.IncorrectClientData;

        if (clientData.Challenge == null || !Settings.Challenge.SequenceEqual(clientData.Challenge))
            return WebAuthnResult.IncorrectChallenge;

        if (string.Compare(clientData.Origin, Settings.Origin, StringComparison.InvariantCultureIgnoreCase) != 0)
            return WebAuthnResult.IncorrectOrigin;

        var authenticatorData = new WebAuthnAuthenticatorData(parms.AuthenticatorData);
        var computedRpIdHash  = Hasher.ComputeHash(Encoding.UTF8.GetBytes(Settings.RelyingPartyId));
        if (!authenticatorData.RelayPartyIdHash.SequenceEqual(computedRpIdHash))
            return WebAuthnResult.IncorrectRelayPartyId;

        if (!authenticatorData.Flags.HasFlag(WebAuthnFlags.UserPresent))
            return WebAuthnResult.UserNotPresent;

        // todo check & verify clientExtensionResults

        var isValid = verifySignature(parms.AuthenticatorData, parms.ClientData, parms.Signature, user.PublicKey);
        if (!isValid)
            return WebAuthnResult.IncorrectSignature;

        if (UserFactory.CounterSupported && authenticatorData.Counter > 0) // authenticatorData.Counter == 0 - token DOESN'T support operation increment 
        {
            if (user.Counter >= authenticatorData.Counter)
                return WebAuthnResult.ClonedToken;
            UserFactory.UpdateCounter(parms.CredentialId, authenticatorData.Counter);
        }

        return WebAuthnResult.OK;
    }

    bool verifySignature(byte[] authenticatorData, byte[] clientDataJson, byte[] signature, string userPublicKey)
    {
        var hash = Hasher.ComputeHash(clientDataJson);

        // signature = authenticatorData + hash
        var sigBase = new byte[authenticatorData.Length + hash.Length];
        authenticatorData.CopyTo(sigBase, 0);
        hash.CopyTo(sigBase, authenticatorData.Length);

        return toECDsa(userPublicKey).VerifyData(sigBase, deserializeSignature(signature), HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// convert ECDsa key from JSON representation:
    /// {"1":2,"3":-7,"-1":1,"-2":"8JWzZz_oJb-R30bdM2SsCxdXKBf9KoEsdrG9LmJ2qGI","-3":"sbmDptpn35h0eypH9o4RWufmvYKToJqPxF-f89eqvx8"}
    /// </summary>
    internal ECDsa toECDsa(string userPublicKey)
    {
        var jo = JsonNode.Parse(userPublicKey) as JsonObject;
        ArgumentNullException.ThrowIfNull(jo);

        var jsonConverter = new JavascriptBase64();
        var keyType       = jo.First(p => p.Key == "1").Value!.GetValue<int>();
        var algorithm     = jo.First(p => p.Key == "3").Value!.GetValue<int>();
        var curve         = jo.First(p => p.Key == "-1").Value!.GetValue<int>();

        var x = JavascriptBase64.FromBase64(jo.First(p => p.Key == "-2").Value!.GetValue<string>());
        var y = JavascriptBase64.FromBase64(jo.First(p => p.Key == "-3").Value!.GetValue<string>());

        return ECDsa.Create(new ECParameters()
                            {
                                Curve = ECCurve.NamedCurves.nistP256,
                                Q = new ECPoint()
                                    {
                                        X = x,
                                        Y = y
                                    }
                            });
    }

    internal byte[] deserializeSignature(byte[] signatureBinary)
    {
        byte[] removeAnyNegativeFlag(byte[] input)
        {
            if (input[0] != 0) return input;

            var output = new byte[input.Length - 1];
            Array.Copy(input, 1, output, 0, output.Length);
            return output;
        }

        // https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1
        using var ms     = new MemoryStream(signatureBinary);
        var       header = ms.ReadByte(); // marker
        var       b1     = ms.ReadByte(); // length of remaining bytes

        var markerR = ms.ReadByte(); // marker
        var b2      = ms.ReadByte(); // length of vr
        var vr      = new byte[b2];  // signed big-endian encoding of r
        ms.Read(vr, 0, vr.Length);
        vr = removeAnyNegativeFlag(vr); // r

        var markerS = ms.ReadByte(); // marker 
        var b3      = ms.ReadByte(); // length of vs
        var vs      = new byte[b3];  // signed big-endian encoding of s
        ms.Read(vs, 0, vs.Length);
        vs = removeAnyNegativeFlag(vs); // s

        var parsedSignature = new byte[vr.Length + vs.Length];
        vr.CopyTo(parsedSignature, 0);
        vs.CopyTo(parsedSignature, vr.Length);

        return parsedSignature;
    }
}