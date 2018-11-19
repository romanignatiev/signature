using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Text;

using Newtonsoft.Json.Linq;

using Xunit;

namespace Signature
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var digestData = Encoding.UTF8.GetBytes(File.ReadAllText("c:\\Projects\\Payload\\digest_replay.txt"));
            var signatureRequest = File.ReadAllText("c:\\Projects\\Payload\\goz_replay_1.request");
            dynamic data = JObject.Parse(signatureRequest);

            var signature = Convert.FromBase64String((string)data.signature);

            var contentInfo = new ContentInfo(digestData);
            var signedCms = new SignedCms(contentInfo, true);

            signedCms.Decode(signature);

            var enumerator = signedCms.SignerInfos.GetEnumerator();
            while (enumerator.MoveNext())
            {
                var signer = enumerator.Current;

                signer.CheckSignature(true);
                break;
            }
        }
    }
}
