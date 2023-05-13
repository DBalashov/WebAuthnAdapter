using System;
using System.IO;
using PeterO.Cbor;

namespace WebAuthn;

sealed class WebAuthnAttestation
{
    /// <summary> 64 bytes </summary>
    internal readonly byte[] CredentialId;

    internal readonly byte[]        RelayPartyIdHash;
    internal readonly uint          Counter;
    internal readonly WebAuthnFlags Flags;
    internal readonly string        PublicKey;

    internal WebAuthnAttestation(byte[] from)
    {
        using var stream = new MemoryStream(from);
        var       cbor   = CBORObject.Read(stream);
        // cbor:
        // {"fmt": "none",
        // "attStmt": {},
        // "authData": h'49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000019000000000000000000000000000000000040A8840357E46D939C51E074680B422F9EFFBA98716827DE4C03D35F9E4959B065B1C4F1CB4F368C5B85A9954D11D339F9F8CDBF9A7ECA9C9834C3307C3D71543AA5010203262001215820149A969FF7F125D72967CB4516A96D6044DA6C593EBD0E3537FE529811D34363225820BB821B6EE177EFD11B96E94F58E20383C3A725C2229908B2B387F2A86FBA7162'}
        var format = cbor["fmt"].AsString();

        var span = cbor["authData"].GetByteString().AsSpan();
        var offs = 0;

        RelayPartyIdHash =  span.Slice(offs, 32).ToArray();
        offs             += 32;

        Flags = (WebAuthnFlags) span[offs];
        offs++;

        Counter =  span.Slice(offs, 4).ToUInt32_BigEndian(); // https://www.w3.org/TR/webauthn/#signature-counter
        offs    += 4;

        var aaGUID = new Guid(span.Slice(offs, 16));
        offs += 16;

        var credentialIdLength = (int) span.Slice(offs).ToUInt16_BigEndian();
        offs += 2;

        CredentialId =  span.Slice(offs, credentialIdLength).ToArray();
        offs         += credentialIdLength;

        PublicKey = CBORObject.DecodeFromBytes(span.Slice(offs).ToArray()).ToJSONString();
    }

#if DEBUG
    public override string ToString() => $"[{Counter}/{Flags}] {Convert.ToBase64String(CredentialId)}, {PublicKey}";
#endif
}

[Flags]
internal enum WebAuthnFlags
{
    UserPresent = 1 << 0,

    // Bit 1 reserved for future use (RFU1)
    UserVerified = 1 << 2,

    // Bits 3-5 reserved for future use (RFU2)
    CredentialData     = 1 << 6, // AT - "attested credential data" present
    ExtensionsIncluded = 1 << 7
}