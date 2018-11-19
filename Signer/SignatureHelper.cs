using System.IO;

using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Signer
{
    public class SignatureHelper
    {
        public static byte[] Sign(byte[] data, string certificatePath, string keyPath, string password)
        {
            var certParser = new X509CertificateParser();
            var certificate = certParser.ReadCertificate(File.ReadAllBytes(certificatePath));

            AsymmetricKeyParameter asymmetricKey;

            using (var keyReader = new StreamReader(keyPath))
            {
                var pem = new PemReader(keyReader);
                asymmetricKey = (AsymmetricKeyParameter)pem.ReadObject();
            }

            var generator = new CmsSignedDataGenerator();
            generator.AddSigner(
                asymmetricKey,
                certificate,
                CmsSignedGenerator.EncryptionEcgost34102012256,
                CmsSignedGenerator.DigestGost3412012256);

            generator.AddCertificates(
                X509StoreFactory.Create(
                    "Certificate/Collection",
                    new X509CollectionStoreParameters(new[] { certificate })));
            return generator.Generate(new CmsProcessableByteArray(data), false)
                .GetEncoded();
        }
    }
}
