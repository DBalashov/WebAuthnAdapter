namespace WebAuthn;

/// <param name="AttestationObject">CBOR binary object</param>
public sealed record WebAuthnRegisterParams(WebAuthnClientData ClientData,
                                        string         UserName,
                                        byte[]?        AttestationObject);