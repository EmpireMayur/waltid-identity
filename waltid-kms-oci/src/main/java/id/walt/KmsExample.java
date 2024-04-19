package id.walt;

import com.oracle.bmc.auth.AuthenticationDetailsProvider;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.KmsManagementClient;
import com.oracle.bmc.keymanagement.KmsVaultClient;
import com.oracle.bmc.keymanagement.model.*;
import com.oracle.bmc.keymanagement.requests.*;
import com.oracle.bmc.keymanagement.responses.*;

import java.util.Base64;

public class KmsExample  {

    private static final int DEFAULT_KEY_LENGTH = 32;
    // The KeyShape used for testing
    private static final KeyShape TEST_KEY_SHAPE =
            KeyShape.builder().algorithm(KeyShape.Algorithm.Ecdsa).length(DEFAULT_KEY_LENGTH).curveId(KeyShape.CurveId.NistP256).build();

    public static Key createKeyTest(
            KmsManagementClient kmsManagementClient, String compartmentId) {
        System.out.println("CreateKey Test");
        CreateKeyDetails createKeyDetails =
                CreateKeyDetails.builder()
                        .keyShape(TEST_KEY_SHAPE)
                        .protectionMode(CreateKeyDetails.ProtectionMode.Software)
                        .compartmentId(compartmentId)
                        .displayName("Test_Key_V1")
                        .build();
        CreateKeyRequest createKeyRequest =
                CreateKeyRequest.builder().createKeyDetails(createKeyDetails).build();
        CreateKeyResponse response = kmsManagementClient.createKey(createKeyRequest);
        System.out.println("Creating a new key: ");
        System.out.println(response.getKey());
        System.out.println();
        return response.getKey();
    }

    public static void signAndVerifyText(
            KmsCryptoClient kmsCryptoClient, AuthenticationDetailsProvider provider, String keyId, String keyVersionId
    ) {
        String textToSign = encodeToBase64("Hello WaltID!");




        // Sign the text
        SignedData signedData = signText(provider, keyId, textToSign , kmsCryptoClient.getEndpoint() , keyVersionId);
        String signature = signedData.getSignature();
        System.out.println("Signature: " + signature);

        // Verify the signature
        boolean verified = verifySignature(provider, keyId, textToSign, signedData , kmsCryptoClient.getEndpoint());
        System.out.println("Signature verified: " + verified);
        System.out.println();
    }
    public static String encodeToBase64(String text) {
        byte[] bytesToEncode = text.getBytes();
        byte[] encodedBytes = Base64.getEncoder().encode(bytesToEncode);
        return new String(encodedBytes);
    }
    public static SignedData signText(
            AuthenticationDetailsProvider provider, String keyId, String textToSign, String endpoint , String keyVersionId) {
        System.out.println("Sign Text Test");
        KmsCryptoClient kmsCryptoClient = KmsCryptoClient.builder().endpoint(endpoint).build(provider);


        SignDataDetails signDataDetails =
                SignDataDetails.builder()
                        .keyId(keyId)
                        .message(textToSign)
                        .messageType(SignDataDetails.MessageType.Raw)
                        .signingAlgorithm(SignDataDetails.SigningAlgorithm.EcdsaSha256)
                        .keyVersionId(keyVersionId)
                        .build();

        System.out.println("SignDataDetails: " + signDataDetails);
        SignRequest signRequest =
                SignRequest.builder().signDataDetails(signDataDetails).build();

        System.out.println("SignRequest: " + signRequest);
        SignResponse response = kmsCryptoClient.sign(signRequest);
        System.out.println("Text to sign: " + textToSign);
        return response.getSignedData();
    }


    public static boolean verifySignature(
            AuthenticationDetailsProvider provider, String keyId, String textToVerify, SignedData signedData , String endpoint) {
        System.out.println("Verify Signature Test");
        KmsCryptoClient kmsCryptoClient = KmsCryptoClient.builder().endpoint(endpoint).build(provider);
        VerifyDataDetails verifyDataDetails =
                VerifyDataDetails.builder()
                        .keyId(keyId)
                        .message(textToVerify)
                        .signature(new String(signedData.getSignature()))
                        .signingAlgorithm(VerifyDataDetails.SigningAlgorithm.EcdsaSha256)
                        .build();
        VerifyRequest verifyRequest =
                VerifyRequest.builder().verifyDataDetails(verifyDataDetails).build();
        VerifyResponse response = kmsCryptoClient.verify(verifyRequest);
        return response.getVerifiedData().getIsSignatureValid();
    }

    public static void setKmsManagementClientEndpoint(KmsManagementClient kmsManagementClient, KmsVaultClient kmsVaultClient, String vaultId) {
        Vault vault = getVaultTest(kmsVaultClient, vaultId);
        kmsManagementClient.setEndpoint(vault.getManagementEndpoint());

    }

    public static Vault getVaultTest(KmsVaultClient kmsVaultClient, String vaultId) {
        System.out.println("GetVault Test");
        GetVaultRequest getVaultRequest = GetVaultRequest.builder().vaultId(vaultId).build();
        GetVaultResponse response = kmsVaultClient.getVault(getVaultRequest);
        System.out.println("Vault retrieved: ");
        System.out.println(response.getVault());
        System.out.println();
        return response.getVault();
    }
}
