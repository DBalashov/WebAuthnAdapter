using System.IO;

namespace WebAuthn;

public static class WebAuthnScript
{
    const string SCRIPT_NAME = "WebAuthn.Script.common.js";

    /// <summary>
    /// <pre>
    /// &lt;script type="text/javascript"&gt;
    /// @Html.Raw(WebAuthnScript.Get())
    /// &lt;/script&gt;
    /// </pre>
    /// </summary>
    public static string Get()
    {
        using var stream = typeof(WebAuthnScript).Assembly.GetManifestResourceStream(SCRIPT_NAME);
        if (stream == null) throw new InvalidDataException("Can't find resource: " + SCRIPT_NAME);

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}