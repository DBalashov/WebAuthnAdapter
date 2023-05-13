namespace WebAuthn;

/// <param name="ClientData">WebAuthnClientData</param>
/// <param name="CredentialId">64 bytes</param>
/// <param name="UserName"></param>
/// <param name="AuthenticatorData">CBOR encoded</param>
/// <param name="Signature">72 bytes</param>
public sealed record WebAuthnAuthenticateParams(byte[] ClientData,
                                                byte[] CredentialId,
                                                string UserName,
                                                byte[] AuthenticatorData,
                                                byte[] Signature);