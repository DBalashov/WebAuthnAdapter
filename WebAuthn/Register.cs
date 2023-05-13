using Microsoft.Extensions.DependencyInjection;

namespace WebAuthn;

public static class Register
{
    /// <summary>
    /// <code>
    /// Must be registered:
    /// WebAuthnSettings - scoped
    /// IWebAuthnUserFactory - scoped
    /// </code>
    /// </summary>
    /// <param name="s"></param>
    /// <returns></returns>
    public static IServiceCollection AddWebAuthn(this IServiceCollection s)
    {
        s.AddScoped<IWebAuthnRegistrator, WebAuthnRegistrator>();
        s.AddScoped<IWebAuthnAuthenticator, WebAuthnAuthenticator>();
        return s;
    }
}