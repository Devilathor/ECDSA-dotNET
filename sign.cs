using System;
using System.Security.Cryptography;
using System.Text;

class ECSign
{
    static void Main(string[] args)
    {
        try
        {
            // Create a UnicodeEncoder to convert between byte array and string.
            ASCIIEncoding ByteConverter = new ASCIIEncoding();

            var currentDirectory = System.AppDomain.CurrentDomain.BaseDirectory;

            // The string to be signed is passed as an argument
            string dataString = System.IO.File.ReadAllText(currentDirectory + args[0]);
            string skey = System.IO.File.ReadAllText(currentDirectory + args[1]);

            // Keys are imported
            byte[] privkey = Convert.FromBase64String(skey);
            CngKey key = CngKey.Import(privkey, CngKeyBlobFormat.Pkcs8PrivateBlob);
            
            ECDsaCng dsa = new ECDsaCng(key);

            // Create byte arrays to hold original and signed data.
            byte[] originalData = ByteConverter.GetBytes(dataString);
            byte[] signedData;
            
            // Hash and sign the data.  
            signedData = dsa.SignData(originalData, HashAlgorithmName.SHA512);

            System.IO.File.WriteAllBytes(currentDirectory + "signature", signedData);
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("The data was not signed or verified");
        }
    }
}
