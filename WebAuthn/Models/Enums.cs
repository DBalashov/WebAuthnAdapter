namespace WebAuthn;

public enum WebAuthnResult
{
    OK,

    #region Registration errors

    /// <summary> trying to register token on different user (userName) </summary>
    DuplicateCredential,

    /// <summary> userName field is empty </summary>
    UserEmpty,

    #endregion

    #region Authentication errors

    /// <summary> invalid credentialId (incompatible) </summary>
    IncorrectKey,

    /// <summary> invalid userName inside client data (incompatible token) </summary>
    IncorrentUserName,

    /// <summary> authentication counter in token less than in user from UserFactory -> may be cloned token </summary>
    ClonedToken,

    /// <summary> mismatch signature (mitm, invalid public key, forgery, replay attack, ...) </summary>
    IncorrectSignature,

    /// <summary> client data doesn't contain user information (incompatible token) </summary>
    UserNotPresent,

    /// <summary> can't found user - UserFactory return null by CredentialId </summary>
    UserNotFound,

    #endregion

    #region Authentication/Registration common errors

    /// <summary> broken client data (invalid token, invalid request, mitm, replay attack, ...) </summary>
    IncorrectClientData,

    /// <summary> invalid origin (invalid request, reverse proxy, ...) </summary>
    IncorrectOrigin,

    /// <summary> same as IncorrectOrigin, but for relying party field </summary>
    IncorrectRelayPartyId,

    /// <summary> invalid challenge (invalid request, mitm, replay attack, ...) </summary>
    IncorrectChallenge,

    #endregion
}