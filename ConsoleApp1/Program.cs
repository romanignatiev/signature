using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

using Newtonsoft.Json.Linq;

namespace ConsoleApp1
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var digestData = Encoding.UTF8.GetBytes(File.ReadAllText("digest.txt"));

            var signatureRequest = File.ReadAllText("POST_req_sign.txt");

            dynamic data = JObject.Parse(signatureRequest);

            var signature = Convert.FromBase64String((string)data.signature);

            ValidateSignature(digestData, signature);

            File.WriteAllBytes("c:\\Projects\\Payload\\payload_sign.p7s", signature);

            signature = File.ReadAllBytes("test test test.p7s");

            ValidateSignature(digestData, signature);

            Console.ReadKey();
        }

        private static void ValidateSignature(byte[] digestData, byte[] signature)
        {
            var contentInfo = new ContentInfo(digestData);
            var signedCms = new SignedCms(contentInfo, true);

            signedCms.Decode(signature);

            var enumerator = signedCms.SignerInfos.GetEnumerator();
            while (enumerator.MoveNext())
            {
                var current = enumerator.Current;
                if (current.Certificate != null)
                {
                    Console.WriteLine(
                        "Проверка подписи для подписавшего '{0}'...",
                        current.Certificate.SubjectName.Name);
                }
                else
                {
                    Console.WriteLine("Проверка подписи для подписавшего без сертификата...");
                }

                try
                {
                    current.CheckSignature(true);
                    Console.WriteLine("Успешно.");
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine("Ошибка:");
                    Console.WriteLine("\t" + e.Message);
                }
            }
        }
    }
}
