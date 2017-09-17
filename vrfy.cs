using System;
using System.Security.Cryptography;
using System.Text;

class ECvrfy
{
    static void Main(string[] args)
    {
        try
        {
            // Create a UnicodeEncoder to convert between byte array and string.
            ASCIIEncoding ByteConverter = new ASCIIEncoding();

            var currentDirectory = System.AppDomain.CurrentDomain.BaseDirectory;

            // Data
            string dataString = System.IO.File.ReadAllText(currentDirectory + args[0]);

            // Signature
            byte[] Signature = System.IO.File.ReadAllBytes(currentDirectory + args[1]);

            string privkeybase64 = System.IO.File.ReadAllText(currentDirectory + args[2]);

            byte[] privkey = Convert.FromBase64String(privkeybase64);
            CngKey key = CngKey.Import(privkey, CngKeyBlobFormat.GenericPublicBlob);

            ECDsaCng dsa = new ECDsaCng(key);

            // The data is given as a string, we must convert it into a byte array
            byte[] originalData = ByteConverter.GetBytes(dataString);
            
            // This is the check
            if (dsa.VerifyData(originalData, Signature, HashAlgorithmName.SHA512))
            {
                Console.WriteLine("The signature is correct");
            }
            else
            {
                Console.WriteLine("The signature is not correct");
            }
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("Something bad");
        }
    }
}
