using System.Text.Json;

namespace WebAuthn.Example;

public record User(byte[] CredentialId,
                   string UserName,
                   string PublicKey,
                   uint   Counter) : IWebAuthnUser;

class UserFactory : IWebAuthnUserFactory
{
    readonly string fileName;

    public bool CounterSupported => false;

    public UserFactory(string fileName) =>
        this.fileName = Path.Combine(Path.GetTempPath(), fileName);

    public IWebAuthnUser? Get(byte[] credentialId)
    {
        var users = JsonSerializer.Deserialize<List<User>>(File.Exists(fileName) ? File.ReadAllText(fileName) : "[]");
        return users?.FirstOrDefault(c => c.CredentialId.SequenceEqual(credentialId));
    }

    public void Set(IWebAuthnUser rr)
    {
        var users = JsonSerializer.Deserialize<List<User>>(File.Exists(fileName) ? File.ReadAllText(fileName) : "[]");
        users!.Add(new User(rr.CredentialId, rr.UserName, rr.PublicKey, rr.Counter));
        File.WriteAllText(fileName, JsonSerializer.Serialize(users, new JsonSerializerOptions() { WriteIndented = true}));
    }

    public User? GetUser(string userName)
    {
        var users = JsonSerializer.Deserialize<List<User>>(File.Exists(fileName) ? File.ReadAllText(fileName) : "[]");
        return users!.FirstOrDefault(p => p.UserName == userName);
    }

    public void UpdateCounter(byte[] credentialId, uint counter)
    {
        var users = JsonSerializer.Deserialize<List<User>>(File.Exists(fileName) ? File.ReadAllText(fileName) : "[]");
        var index = users!.FindIndex(p => p.CredentialId.SequenceEqual(credentialId));
        if (index < 0) return;

        users[index] = users[index] with {Counter = counter};
        File.WriteAllText(fileName, JsonSerializer.Serialize(users, new JsonSerializerOptions() { WriteIndented = true}));
    }
}