using Common;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ConsoleClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(new RSAParameters
            {
                Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                Modulus = Base64UrlEncoder.DecodeBytes("14WuP4Q4BQ6rkwHBIrO8PjArlbSPlPwLRVw4tfzA80I_VOPdqeRmQ_xV2HznKGQCG37sKCq3G-UhIaitYUyW-I_xbqIPKPvPbp9iWd0mg96j0UizdkMj2sc_z5dxTPK9tkoeOrwAm6JSyGG8ksEtpivM_CWCdMslBAsjXmtrQpJ2CE5SunrURGl_uKrSZzV6g_nltrdH3Mi4ebQrLYkfHLbwe0OiTXellyeLrH0C3wYkEnftz8yQ8g4n9VYGaNaclWk2CfjcO5hApQfSJsv7xrmdH2C0Qn5yE85LUqsqlR9cNo7T5A_1d-V1iBxiBXgYr4jB_VwZdLUXr1pScJ_w9Q")
            });

            var publicKey = RSAKeys.ExportPublicKey(rsaProvider);

            Console.WriteLine("\n\n");
        }
    }
}
