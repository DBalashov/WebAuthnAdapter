namespace WebAuthn;

/// <param name="Challenge">must be 16 bytes</param>
/// <param name="RelyingPartyId"></param>
/// <param name="Origin">schema, domain and port (like: https://localhost)</param>
public sealed record WebAuthnSettings(byte[] Challenge, string RelyingPartyId, string Origin);