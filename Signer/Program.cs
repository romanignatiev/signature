using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CommandLine;

namespace Signer
{
    public class Program
    {
        private static void Main(string[] args)
        {

            

            /*String signer = "D:\\Rutoken\\Ustinkin\\Signature\\Signer\\2975511090.client.cer";
            String inkey = "D:\\Rutoken\\Ustinkin\\Signature\\Signer\\2975511090.privkey_decoded.pem";
            String password = "1234";
            String inputFile = "D:\\Rutoken\\Ustinkin\\Signature\\Signer\\digest.txt";

            var dataToSign = File.ReadAllBytes(inputFile);
            byte[] dataToSign = Encoding.ASCII.GetBytes("kek"); ;
            var signature = SignatureHelper.Sign(dataToSign, signer, inkey, password);

            String result = Convert.ToBase64String(signature);

            File.WriteAllText("D:\\Rutoken\\Ustinkin\\Signature\\Signer\\output.der", result);

            Console.WriteLine("Signed successfully");*/



        }

        /*private static void RunOptionsAndReturnExitCode(Options opts)
        {
            try
            {
                foreach (var inputFile in opts.InputFiles)
                {
                    var dataToSign = File.ReadAllBytes(inputFile);
                    var signature = SignatureHelper.Sign(dataToSign, opts.Signer, opts.InputKey, opts.KeyPassword);

                    File.WriteAllBytes(Path.ChangeExtension(inputFile, "p7s"), signature);

                    Console.WriteLine("Signed successfully");

                    Verify(inputFile, dataToSign);
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e);
                Console.ResetColor();
            }
        }

        private static byte[] SignMsg(byte[] msg, X509Certificate2 signerCert)
        {
            // Создаем объект ContentInfo по сообщению.
            // Это необходимо для создания объекта SignedCms.
            var contentInfo = new ContentInfo(msg);

            // Создаем объект SignedCms по только что созданному
            // объекту ContentInfo.
            // SubjectIdentifierType установлен по умолчанию в 
            // IssuerAndSerialNumber.
            // Свойство Detached установлено по умолчанию в false, таким 
            // образом сообщение будет включено в SignedCms.
            var signedCms = new SignedCms(contentInfo, true);

            // Определяем подписывающего, объектом CmsSigner.
            var cmsSigner = new CmsSigner(signerCert);

            // Подписываем CMS/PKCS #7 сообение.
            Console.Write("Вычисляем подпись сообщения для субъекта " + "{0} ... ", signerCert.SubjectName.Name);
            signedCms.ComputeSignature(cmsSigner);
            Console.WriteLine("Успешно.");

            // Кодируем CMS/PKCS #7 сообщение.
            return signedCms.Encode();
        }

        */




        
        public static String SignAuthToken(string signer, string inkey, string inputString)
        {
            /*Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptionsAndReturnExitCode);*/

            //String signer = "2975511090.client.cer";
            //String inkey = "2975511090.privkey_decoded.pem";
            String password = "1234";
            /*String inputFile = "D:\\Rutoken\\Ustinkin\\Signature\\Signer\\digest.txt";

            var dataToSign = File.ReadAllBytes(inputFile);*/
            byte[] dataToSign = Encoding.UTF8.GetBytes(inputString); ;
            var signature = SignatureHelper.Sign(dataToSign, signer, inkey, password);

            String result = Convert.ToBase64String(signature);

            //File.WriteAllText("D:\\Rutoken\\Ustinkin\\Signature\\Signer\\output.der", result);

            Console.WriteLine("Signed successfully");

            return result;


        }


        public static String SignFile(string signer, string inkey, string inputFile)
        {
             
            String password = "1234";
            //String inputFile = "D:\\Rutoken\\Ustinkin\\Signature\\Signer\\digest.txt";

            var dataToSign = File.ReadAllBytes(inputFile);
            //byte[] dataToSign = Encoding.UTF8.GetBytes(dataToSign); 
            var signature = SignatureHelper.Sign(dataToSign, signer, inkey, password);

            String result = Convert.ToBase64String(signature);

            //File.WriteAllText("D:\\Rutoken\\Ustinkin\\Signature\\Signer\\output.der", result);

            Console.WriteLine("Signed successfully");

            return result;


        }




    /*private static void Verify(string inputFile, byte[] data)
    {
        var signFile = Path.ChangeExtension(inputFile, "p7s");

        var contentInfo = new ContentInfo(data);
        var signedCms = new SignedCms(contentInfo, true);

        signedCms.Decode(File.ReadAllBytes(signFile));

        var enumerator = signedCms.SignerInfos.GetEnumerator();
        while (enumerator.MoveNext())
        {
            var current = enumerator.Current;
            if (current.Certificate != null)
            {
                Console.WriteLine("Проверка подписи для подписавшего '{0}'...", current.Certificate.SubjectName.Name);
            }
            else
            {
                Console.WriteLine("Проверка подписи для подписавшего без сертификата...");
            }

            try
            {
                // Используем проверку подписи и стандартную 
                // процедуру проверки сертификата: построение цепочки, 
                // проверку цепочки, и необходимых расширений для данного 
                // сертификата.
                current.CheckSignature(false);
                Console.WriteLine("Успешно.");
            }
            catch (Exception e)
            {
                Console.WriteLine("Ошибка:");
                Console.WriteLine("\t" + e.Message);
            }
        }
    }*/
}
}
