using System.Text.Json.Serialization;

namespace WebAuthn;

/// <summary> {"type":"webauthn.create","challenge":"3YHjbzf3ZdEebd_EhJCXuw","origin":"http://localhost:5000","crossOrigin":false} </summary>
public sealed record WebAuthnClientData([property: JsonPropertyName("challenge"), JsonConverter(typeof(JavascriptBase64))]
                                        byte[]? Challenge,
                                        [property: JsonPropertyName("origin")] string Origin,
                                        [property: JsonPropertyName("crossOrigin")]
                                        bool CrossOrigin,
                                        [property: JsonPropertyName("type")] string Type);