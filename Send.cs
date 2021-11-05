using SentinelVaultClient.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device;
using vm.data.library.blockchain.api.device.Model;


namespace SentinelVaultClient
{
    public class Send
    {
       
        public static string  AddCollectable (string name, byte[] content)
        {
            DeviceSecureIdentity id = Device.GetDeviceSecureIdentity(name);
            Collectable obj = new Collectable();
            obj.ObjectID = Guid.NewGuid();
            // Digital Object
            obj.Content = content;
            obj.ContentHash = Device.ComputeHash(content);
            obj.ContentSignature = Device.SignHash(name, obj.ContentHash);
            // Creator
            obj.ObjectCreator = id.sin;
            obj.ObjectCreatorPublicKey = id.ecdsa_PublicKeyBlob;
            obj.ObjectCreatorExchangeKey = id.ecdh_PublicKeyBlob;
            // Owner
            byte[] ownerObjHash = Device.ComputeHash(obj.ObjectID.ToByteArray().Concat(obj.ContentHash).ToArray());
            obj.ObjectOwnerSignature = Device.SignHash(name, ownerObjHash);

            // Add Host details
            obj.VaultSecureIdentity = id.host_sin;
            obj.VaultEcdhPublicKey = id.host_sin_ecdh_PublicKeyBlob;

           // Setup HTTP Post
            HttpClient _httpClient = new(); 
            String _uri = "http://localhost:7071/api/VaultAddObject";
            _httpClient.BaseAddress = new Uri(_uri);
            try
            {
                // Post Content
                HttpResponseMessage response = _httpClient.PostAsJsonAsync(_uri, obj).Result;
                // Returned Vaulted object
                string sjson = response.Content.ReadAsStringAsync().Result;
                return sjson;
            }
            catch (Exception ex)
            {
                throw new Exception("Error: " + ex.ToString());
            }
        }


    }
}
