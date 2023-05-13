using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn;

static class Extenders
{
    internal static uint ToUInt16_BigEndian(this Span<byte> span) =>
        ((uint) span[0]) << 8 | span[1];

    internal static uint ToUInt32_BigEndian(this Span<byte> span) =>
        BitConverter.ToUInt32(new[] {span[3], span[2], span[1], span[0]}, 0);
}

sealed class JavascriptBase64 : JsonConverter<byte[]>
{
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => 
        reader.TokenType == JsonTokenType.Null ? null : FromBase64(reader.GetString()!);

    internal static byte[] FromBase64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return (s.Length % 4) switch
               {
                   0 => Convert.FromBase64String(s),
                   2 => Convert.FromBase64String(s + "=="),
                   3 => Convert.FromBase64String(s + "="),
                   _ => throw new Exception("Illegal base64 string!")
               };
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options) => 
        throw new NotImplementedException();
}