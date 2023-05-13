namespace WebAuthn;

sealed record WebAuthnRegistratorResult(string UserName,
                                        byte[] CredentialId,
                                        string PublicKey,
                                        uint   Counter) : IWebAuthnUser;