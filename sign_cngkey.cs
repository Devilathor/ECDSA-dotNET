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

            // Keys are imported
            CngKey Skey = CngKey.Open("key1");
            ECDsaCng dsa = new ECDsaCng(Skey);

            // Create byte arrays to hold original and signed data.
            byte[] originalData = ByteConverter.GetBytes(dataString);
            byte[] signedData;
            
            //Hash and sign the data.  
            signedData = dsa.SignData(originalData, HashAlgorithmName.SHA512);

            System.IO.File.WriteAllBytes(currentDirectory + "signature", signedData);
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("The data was not signed or verified");
        }
    }
}
