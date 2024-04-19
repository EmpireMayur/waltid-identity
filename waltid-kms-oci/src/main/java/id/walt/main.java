package id.walt;


import com.oracle.bmc.ConfigFileReader;
import com.oracle.bmc.auth.AuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.KmsManagementClient;
import com.oracle.bmc.keymanagement.KmsVaultClient;
import com.oracle.bmc.keymanagement.model.KeyShape;
import com.oracle.bmc.keymanagement.model.Vault;

import static id.walt.KmsExample.*;

public class main {



//    // Please pass in the compartmentId and the vaultId as the first and second argument
//    public static void main(final String[] args) throws Exception {
//
//        // Read in compartmentId and vaultId and perform basic validations.
//        final String compartmentId = "ocid1.compartment.oc1..aaaaaaaawirugoz35riiybcxsvf7bmelqsxo3sajaav5w3i2vqowcwqrllxa";
//        final String vaultId = "ocid1.vault.oc1.eu-frankfurt-1.entbf645aabf2.abtheljshkb6dsuldqf324kitneb63vkz3dfd74dtqvkd5j2l2cxwyvmefeq";
//
//        final String configurationFilePath = "~/.oci/config";
//        final String profile = "DEFAULT";
//
//        final ConfigFileReader.ConfigFile configFile = ConfigFileReader.parseDefault();
//
//        final AuthenticationDetailsProvider provider =
//                new ConfigFileAuthenticationDetailsProvider(configFile);
//
//        // Create KMS clients
//        KmsVaultClient kmsVaultClient = KmsVaultClient.builder().build(provider);
//
//        Vault vault = getVaultTest(kmsVaultClient, vaultId);
//
//        KmsManagementClient kmsManagementClient = KmsManagementClient.builder().endpoint(vault.getManagementEndpoint()).build(provider);
//
//
//        KmsCryptoClient kmsCryptoClient = KmsCryptoClient.builder().endpoint(vault.getCryptoEndpoint()).build(provider);
//
//
//
//        setKmsManagementClientEndpoint(kmsManagementClient, kmsVaultClient, vaultId);
//
//        System.out.println("kmsVaultClient: " + kmsVaultClient.getEndpoint());
//        System.out.println("kmsManagementClient: " + kmsManagementClient.getEndpoint());
//        System.out.println("kmsCryptoClient: " + kmsCryptoClient.getEndpoint());
//
//
//        // Create a key
//        //   Key key = createKeyTest(kmsManagementClient, compartmentId);
////        String keyId =key.getId();
////
////        String keyVersionId = key.getCurrentKeyVersion();
//        String keyId ="ocid1.key.oc1.eu-frankfurt-1.entbf645aabf2.abtheljrvxdlvr75raatjttj2dsprsk7ago7u4cjyssqd7senwqrcew5g5ha";
//
//        String keyVersionId = "ocid1.keyversion.oc1.eu-frankfurt-1.entbf645aabf2.bciemypxlkyaa.abtheljr5ovdn5un3xuaktoqtwvzockr6b5edoy6on2p5ejfh4l6xqlotx5q";
//        // wait for key to be ready
//        Thread.sleep(5000);
//
//        // Sign and verify text
//        signAndVerifyText(kmsCryptoClient, provider, keyId,keyVersionId);
//    }
}
