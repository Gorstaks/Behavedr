using System.Security.Cryptography;

// Generate RSA-4096 update-signing keypair.
// Private key: update-signing-key.pem (gitignored - never commit)
// Public key:  update-signing-key.pub.pem (committed for operators + bake into agent)

using var rsa = RSA.Create(4096);

var projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
var privateKeyPath = Path.Combine(projectRoot, "update-signing-key.pem");
var publicKeyPath = Path.Combine(projectRoot, "update-signing-key.pub.pem");

var publicPem = rsa.ExportSubjectPublicKeyInfoPem();
var privatePem = rsa.ExportRSAPrivateKeyPem();

File.WriteAllText(privateKeyPath, privatePem + Environment.NewLine);
File.WriteAllText(publicKeyPath, publicPem + Environment.NewLine);

Console.WriteLine(publicPem);
Console.Error.WriteLine($"Private key written to: {privateKeyPath}");
Console.Error.WriteLine($"Public  key written to: {publicKeyPath}");
Console.Error.WriteLine();
Console.Error.WriteLine("NEXT STEPS:");
Console.Error.WriteLine("  1. Copy the PUBLIC key into UpdateSignatureVerifier.PublicKeyPem");
Console.Error.WriteLine("     and PolicySignatureVerifier.PublicKeyPem (or leave policy dual-use).");
Console.Error.WriteLine("  2. Store the PRIVATE key as GitHub secret UPDATE_SIGNING_KEY (full PEM).");
Console.Error.WriteLine("  3. Keep a local offline backup of update-signing-key.pem - never commit it.");
Console.Error.WriteLine("  4. Commercial Authenticode/Apple certs are optional and separate.");
