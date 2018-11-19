using System.Collections.Generic;

using CommandLine;

namespace Signer
{
    internal class Options
    {
        [Option('i', "input", Required = true, HelpText = "Input files to be processed.")]
        public IEnumerable<string> InputFiles { get; set; }

        [Option("signer", Required = true, HelpText = "Input certificate file for sign.")]
        public string Signer { get; set; }

        [Option("inkey", Required = true, HelpText = "Input key file for sign.")]
        public string InputKey { get; set; }

        [Option('p', "passin", Required = true, HelpText = "Input pfx file password.")]
        public string KeyPassword { get; set; }
    }
}
