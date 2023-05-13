using System;

namespace WebAuthn;

sealed record WebAuthnAuthenticatorData
{
    internal readonly byte[]        RelayPartyIdHash;
    internal readonly uint          Counter;
    internal readonly WebAuthnFlags Flags;

    internal WebAuthnAuthenticatorData(byte[] from)
    {
        var span = from.AsSpan();
        var offs = 0;

        RelayPartyIdHash =  span.Slice(0, 32).ToArray();
        offs             += 32;

        Flags = (WebAuthnFlags) span[offs];
        offs++;

        Counter = span.Slice(offs, 4).ToUInt32_BigEndian(); // https://www.w3.org/TR/webauthn/#signature-counter
    }

#if DEBUG
    public override string ToString() => $"[Counter={Counter}]: {Flags}, {RelayPartyIdHash}";
#endif
}