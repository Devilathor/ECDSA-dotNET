using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

public class KeyGen
{
    static void Main()
    {
        try
        {
            ECDsaCng dsa = new ECDsaCng(ECCurve.CreateFromFriendlyName("brainpoolP256t1"));
            CngKey key = dsa.Key;
            
            byte[] exportpriv = key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            String privkeybase64 = Convert.ToBase64String(exportpriv);
            var currentDirectory = System.AppDomain.CurrentDomain.BaseDirectory;
            System.IO.File.WriteAllText(currentDirectory + "skey", privkeybase64);

            byte[] exportpubl = key.Export(CngKeyBlobFormat.GenericPublicBlob);
            String publkeybase64 = Convert.ToBase64String(exportpubl);
            System.IO.File.WriteAllText(currentDirectory + "pkey", publkeybase64);
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("Error");
        }
    }
}
