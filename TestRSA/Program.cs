using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TestRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            var RSAKey = File.ReadAllText("tempkey.rsa", Encoding.UTF8);

            var tempKey = JsonConvert.DeserializeObject<Tempkey>(RSAKey);

            var D = Encoding.UTF8.GetBytes(tempKey.Parameters.D);
                       var DP = Encoding.UTF8.GetBytes(tempKey.Parameters.Dp);
            var DQ = Encoding.UTF8.GetBytes(tempKey.Parameters.Dq);
            var Exponent = Encoding.UTF8.GetBytes(tempKey.Parameters.Exponent);
            var InverseQ = Encoding.UTF8.GetBytes(tempKey.Parameters.InverseQ);
            var Modulus = Encoding.UTF8.GetBytes(tempKey.Parameters.Modulus);
            var P = Encoding.UTF8.GetBytes(tempKey.Parameters.P);
            var Q = Encoding.UTF8.GetBytes(tempKey.Parameters.Q);

            var test = Encoding.UTF8.GetBytes(tempKey.Parameters.D);


            // self signed
            var rsaParams = new RSAParameters
            {
                Exponent = Convert.FromBase64String("AQAB"),
                
                Modulus = Convert.FromBase64String("AJotpUgoUqu9bS2YRkSHcriFbuISf+jVR4GAxbOH/4fz0P5wZO6giv3olXXqSCN3s5VByKg96xHZRQAcHWvPeVjxPimQ2iLCb9+a1HskJtxail1QL9GdJEtUVIAhr0nGcAFLZApAO+iyaZSu9mMYSDj6AexLZfT9kSdhwU0qZYd6/qd/nnNxYWz0ZLFrz7F3VRJma0zyHAT0A5obJQeZFFe6pTGtGJx84oI9zzFvFr5GpNLpbJUOF1JpE3DtHmpv6xDOWpgdpdQUvfTIw2eltiQl8P6qP9AwxRP4v4rxE2ZCIaEx21axMOoQtxyUkT493+Jd9voVM80+V1KkjHY6I/k="),
                
            };

            // development
            var rsaParam2 = new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes("14WuP4Q4BQ6rkwHBIrO8PjArlbSPlPwLRVw4tfzA80I_VOPdqeRmQ_xV2HznKGQCG37sKCq3G-UhIaitYUyW-I_xbqIPKPvPbp9iWd0mg96j0UizdkMj2sc_z5dxTPK9tkoeOrwAm6JSyGG8ksEtpivM_CWCdMslBAsjXmtrQpJ2CE5SunrURGl_uKrSZzV6g_nltrdH3Mi4ebQrLYkfHLbwe0OiTXellyeLrH0C3wYkEnftz8yQ8g4n9VYGaNaclWk2CfjcO5hApQfSJsv7xrmdH2C0Qn5yE85LUqsqlR9cNo7T5A_1d-V1iBxiBXgYr4jB_VwZdLUXr1pScJ_w9Q"),
                Exponent = Base64UrlEncoder.DecodeBytes("AQAB")
            };

            var rsaParam3 = new RSAParameters
            {
                Exponent = Convert.FromBase64String(tempKey.Parameters.Exponent),

                Modulus = Convert.FromBase64String(tempKey.Parameters.Modulus)
            };

            var rsaKey = new RsaSecurityKey(rsaParam2);

            

            using (var provider = new RSACryptoServiceProvider())
            {
                provider.ImportParameters(rsaParam2);
                var myKey2 = ExportPublicKey(provider);
            }

            Console.ReadKey();

            



            

        }

        public static string ExportPublicKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}
