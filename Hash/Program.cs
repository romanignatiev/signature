using System;
using System.IO;
using System.Text;

using CryptoPro.Sharpei;

namespace Hash
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var data = File.ReadAllText(args[0]);
            using (var algorithm = new Gost3411_2012_256CryptoServiceProvider())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(data));

                Console.WriteLine(Convert.ToBase64String(hash));
                Console.ReadKey();
            }
        }
    }
}
