using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Formatting;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device.Model;



namespace SentinelVaultClient
{
    public class Device
    {

               
        public static void SaveDeviceSecureIdentities(DeviceSecureIdentities ids)
        {
            Settings.Default.SECUREIDENTIES = ids.asJason();
            Settings.Default.Save();
        }
        public static DeviceSecureIdentity GetDeviceSecureIdentity(string name)
        {
            DeviceSecureIdentities ids = new DeviceSecureIdentities(Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = (from DeviceSecureIdentity i in ids.identities
                                       where i.label.Equals(name)
                                       select i).SingleOrDefault();
            return id;
        }
        public static void SaveDeviceSecureIdentity(DeviceSecureIdentity id)
        {
            DeviceSecureIdentities ids = new DeviceSecureIdentities(Settings.Default.SECUREIDENTIES);
            // Check if existing
            if (ids.list(id.label).Any())
            {
                // Update
                ids.identities.RemoveAll(chunk => chunk.label == id.label);
                ids.identities.Add(id);
            }
            else
            {
                // Add
                ids.identities.Add(id);
            }
            // Save
            SaveDeviceSecureIdentities(ids);
        }

        public static byte[] GetHostECDHKey(string name)
        {
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            return id.host_sin_ecdh_PublicKeyBlob;
        }

        #region KeyGeneration
        /// <summary>
        /// Generate and Store ECDSA Device Identity Key Pairs
        /// </summary>
        /// <param name="name">Local Label </param>
        /// <param name="sin">Secure Identity</param>
        /// <param name="host_sin">Host Secure Identity</param>
        /// <returns></returns>
        public static string GenECDSAKeys(string name, string entity_sin, string host_sin)
        {
            string sin = Provider.GenECDSAKeys(name);
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            if (id != null)
            {
                // Update Existing
                id.ecdsa_PublicKeyBlob = Provider.GetECDSAPubKey(name);
                id.sin = SecureIdentity(id.ecdsa_PublicKeyBlob); 
            }
            else
            {
                // Add New
                id = new DeviceSecureIdentity
                {
                    label = name,
                    // ECDSA
                    ecdsa_PublicKeyBlob = Provider.GetECDSAPubKey(name)
                };
                id.sin = SecureIdentity(id.ecdsa_PublicKeyBlob);
            }
            // Save 
            SaveDeviceSecureIdentity(id);
            return id.sin;
        }
        /// <summary>
        /// Generate and Store ECDH Key Pairs
        /// </summary>
        public static void GenECDHKeys(string name, string sin, string host_sin)
        {
            Provider.GenECDHKeys(name);
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            if (id != null)
            {
                // Update Existing
                id.ecdh_PublicKeyBlob = Provider.GetECDHPubKey(name);
            }
            else
            {
                // Add New
                id = new DeviceSecureIdentity
                {
                    label = name,
                    entity_sin = sin,
                    host_sin = host_sin,

                    // ECDH
                    ecdh_PublicKeyBlob = Provider.GetECDHPubKey(name)
                };
            }
            // Save 
            SaveDeviceSecureIdentity(id);
        }
        #endregion
        /// <summary>
        /// Sign the SHA256 hash of the data
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] SignHashData(string name, byte[] data)
        {
            using SHA256 dSHA256 = SHA256.Create();
            byte[] hashBytes = dSHA256.ComputeHash(data);
            return SignHash(name, hashBytes);
        }
        public static byte[] ComputeHash(byte[] data)
        {
            using SHA256 dSHA256 = SHA256.Create();
            byte[] hashBytes = dSHA256.ComputeHash(data);
            return hashBytes;
        }
        /// <summary>
        /// Sign the SHA256 Hash
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] SignHash(string name, byte[] hash)
        {

            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            byte[] signature = Provider.SignHash(hash, id.label);
            bool bResult = Provider.VerifyHash(hash, signature, name);
            if (bResult == false)
                throw new Exception("Error: Signature Verify Failed");
            return signature;
        }
        /// <summary>
        /// Sign Data, using provider key store
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] SignData(string name, byte[] data)
        {
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);


            byte[] signature = Provider.SignData(data, id.label);
            bool bResult = Provider.VerifyData(data, signature, name);
            if (bResult == false)
                throw new Exception("Error: Signature Verify Failed");
            return signature;

        }
        /// <summary>
        /// Verify Hash Signature
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hash"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public static bool VerifyHash(string name, byte[] hash, byte[] signature)
        {
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            return Provider.VerifyHash(hash, signature, id.label);
          
        }
        /// <summary>
        /// Verify SHA256 of data, signature
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public static bool VerifyData(string name, byte[] data, byte[] signature)
        {
            DeviceSecureIdentity id = GetDeviceSecureIdentity(name);
            return Provider.VerifyData(data, signature, id.label);
           
        }
        /// <summary>
        /// Retrieve ECDSA Public Key
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static byte[] GetECDSAPubKey(string keyName)
        {
            CngProvider keyProvider = new CngProvider("Microsoft Platform Crypto Provider");
            var k = CngKey.Open(keyName, keyProvider);
            return k.Export(CngKeyBlobFormat.EccPublicBlob);
        }
        /// <summary>
        /// REturn Device Secure Identity
        /// </summary>
        /// <param name="name"></param>
        /// <returns>SIN</returns>
        public static string GetDeviceSecureIdenty(string keyName)
        {

            DeviceSecureIdentity d = new DeviceSecureIdentity();
            d.ecdsa_PublicKeyBlob = GetECDSAPubKey(keyName);
            return SecureIdentity(d.ecdsa_PublicKeyBlob);
        }
        public static string SecureIdentity(byte[] publicKey)
        {
            byte[] hashBytes = RIPEMD160.Create().ComputeHash(SHA256.Create().ComputeHash(publicKey));
            return "0101" + Encoding.UTF8.GetString( hashBytes);
        }
       
        /// <summary>
        /// Generate Key Identifier
        /// </summary>
        /// <param name="PublicKey"></param>
        /// <returns>Key Identifier</returns>
        public static string KeyId(byte[] PublicKey)
        {
            using RIPEMD160 hash = RIPEMD160.Create();
            return Convert.ToBase64String(hash.ComputeHash(PublicKey));

        }

    }
}
