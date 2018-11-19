using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NHttp.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var server = new HttpServer())
            {
                // New requests are signaled through the RequestReceived
                // event.

                server.RequestReceived += (s, e) =>
                {
                    
                    string data = e.Request.RawUrl;
                    Console.WriteLine("Request: {0}", data);


                    var regex = new Regex(@"<cert>(?<certificate_path>.+?)</cert><privkey>(?<private_key_path>.+?)</privkey><sign_type>(?<sign_type>.+?)</sign_type><value>(?<value>.+?)</value>");
                    Match match = regex.Match(data);

                    string cert = match.Groups["certificate_path"].Value;
                    string privkey = match.Groups["private_key_path"].Value;
                    string sign_type = match.Groups["sign_type"].Value;
                    string value = match.Groups["value"].Value;


                    Console.WriteLine("cert: {0}", cert);
                    Console.WriteLine("privkey: {0}", privkey);
                    Console.WriteLine("sign_type: {0}", sign_type);
                    Console.WriteLine("value: {0}", value);

                    string response = null;

                    if (sign_type.Equals("auth"))
                    {
                        response = Signer.Program.SignAuthToken(cert, privkey, value);
                    }

                    if (sign_type.Equals("file"))
                    {
                        response = Signer.Program.SignFile(cert, privkey, value);
                    }

                                  



                    // The response must be written to e.Response.OutputStream.
                    // When writing text, a StreamWriter can be used.

                    using (var writer = new StreamWriter(e.Response.OutputStream))
                    {
                        writer.Write("<signed>{0}</signed>", response);
                        
                    }
                };

                // Start the server on a random port. Use server.EndPoint
                // to specify a specific port, e.g.:
                //
                     server.EndPoint = new IPEndPoint(IPAddress.Loopback, 80);
                //

                server.Start();

                // Start the default web browser.

                Process.Start(String.Format("http://{0}/", server.EndPoint));

                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();

                // When the HttpServer is disposed, all opened connections
                // are automatically closed.
            }
        }
    }
}
