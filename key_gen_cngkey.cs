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
            CngKey key;
            CngKeyCreationParameters keyparm = new CngKeyCreationParameters(); 
            
            // See: https://msdn.microsoft.com/en-us/library/system.security.cryptography.cngexportpolicies(v=vs.110).aspx
            keyparm.ExportPolicy = CngExportPolicies.AllowPlaintextExport;   
            
            keyparm.KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey;  //.MachineKey	.None
            keyparm.Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

            // For different algorithms available see: https://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm(v=vs.110).aspx
            key = CngKey.Create(CngAlgorithm.ECDsaP256, "key1", keyparm);

            // Export public key
            byte[] publkey = key.Export(CngKeyBlobFormat.GenericPublicBlob);
            String publkeybase64 = Convert.ToBase64String(publkey);
            var currentDirectory = System.AppDomain.CurrentDomain.BaseDirectory;
            System.IO.File.WriteAllText(currentDirectory + "pkey", publkeybase64);
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("Error");
        }
    }
}
