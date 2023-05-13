namespace WebAuthn;

public interface IWebAuthnUserFactory
{
    /// <summary> Must be return user if found by credentialId or null if user not found </summary>
    IWebAuthnUser? Get(byte[] credentialId);

    /// <summary> Supporting or counter of token use. If yes - will called UpdateCounter after successful authentication</summary>
    bool CounterSupported { get; }

    void UpdateCounter(byte[] credentialId, uint counter);
}

public interface IWebAuthnRegistrator
{
    WebAuthnResult Register(WebAuthnRegisterParams parms, out IWebAuthnUser outUser);

    /// <summary>
    /// return script for create public key and user interaction with token
    /// script call browser window for optional PIN-code input and token touch
    ///
    /// After this call callbackUrl with WebAuthnRegisterParams and call Process for validate all parameters 
    /// if WebAuthnResult==WebAuthnResult.OK - call JS function with passed name in callbackFunctionSuccess, which usually show message "OK, token registered"
    /// if WebAuthnResult!=WebAuthnResult.OK or user in any moment press "Cancel" (when 'token insert' or 'token touch' prompt, for example) - call callbackFunctionFailed
    ///
    /// Important: during all process - from Registrator instance creation to callbackFunctionSuccess call -
    /// instance of Registrator must be one per user (Challenge and UserName must be saved)
    /// </summary>
    string GetScript(string callbackUrl, string callbackFunctionSuccessName, string callbackFunctionFailedName, string userName);
}

public interface IWebAuthnAuthenticator
{
    WebAuthnResult Authenticate(WebAuthnAuthenticateParams parms);

    /// <summary>
    /// return script for create public key and user interaction with token
    /// script call browser window for optional PIN-code input and token touch
    ///
    /// after this call callbackUrl with WebAuthnAuthenticateParams and call Process for validate all parameters
    ///
    /// if WebAuthnResult==WebAuthnResult.OK - call JS function with name callbackFunctionSuccess, which usually show message "OK, token registered"
    /// if WebAuthnResult!=WebAuthnResult.OK or user in any moment press "Cancel" (when 'token insert' or 'token touch' prompt, for example) - call callbackFunctionFailed 
    ///
    /// important: during all process - from Registrator instance creation to callbackFunctionSuccess call -
    /// instance of Authenticator must be one per user (Challenge and UserName must be saved)
    ///
    /// external user must pass IWebAuthnUserFactory implementation to Process, which find user by userName and credentialID
    /// and after success search and validation AND userFactory.CounterSupported - call UpdateCounter for increment token usage counter
    /// </summary>
    string GetScript(string callbackUrl, string callbackFunctionSuccessName, string callbackFunctionFailedName, IWebAuthnUser user);
}

/// <summary>
/// ALl fields of user - persistent, must not be changed during user life
/// (except Counter, which optionally incremented on each authentication - if CounterSupported in IWebAuthnUserFactory)
/// </summary>
public interface IWebAuthnUser
{
    byte[] CredentialId { get; }
    string UserName     { get; }
    string PublicKey    { get; }

    uint Counter { get; }
}