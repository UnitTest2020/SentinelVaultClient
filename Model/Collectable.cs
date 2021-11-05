using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SentinelVaultClient.Model
{
    public class Collectable
    {
        // Content
        public byte[] Content { get; set; }
        public byte[] ContentHash { get; set; }
        public byte[] ContentSignature { get; set; }
        public byte[] ContentSignaturePublicKey { get; set; }
        public string ContentUri { get; set; }


        // Vaulted Object
        public Guid ObjectID { get; set; }
        public string ObjectState { get; set; }   // Active, Archive, Deleted
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }
        public string ObjectFileName { get; set; }
        public long ObjectSize { get; set; }
        public DateTime ObjectCreationDate { get; set; }

        public string ObjectOwner { get; set; }
        public byte[] ObjectOwnerSignature { get; set; }
        public byte[] ObjectOwnerPublicKey { get; set; }

        public string ObjectCreator { get; set; }
        public byte[] ObjectCreatorPublicKey { get; set; }
        public byte[] ObjectCreatorExchangeKey { get; set; }

        // Vault Provider
        public byte[] VaultEcdhPublicKey { get; set; }
        public string VaultSecureIdentity { get; set; }

        // Shared
        public byte[] EphemeralDhmPublicKeyBlob { get; set; }
    }
}
