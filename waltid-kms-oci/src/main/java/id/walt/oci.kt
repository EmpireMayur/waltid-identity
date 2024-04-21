package id.walt

import com.oracle.bmc.ConfigFileReader
import com.oracle.bmc.auth.AuthenticationDetailsProvider
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider
import com.oracle.bmc.keymanagement.KmsCryptoClient
import com.oracle.bmc.keymanagement.KmsManagementClient
import com.oracle.bmc.keymanagement.KmsVaultClient
import com.oracle.bmc.keymanagement.model.*
import com.oracle.bmc.keymanagement.requests.CreateKeyRequest
import com.oracle.bmc.keymanagement.requests.GetKeyRequest
import com.oracle.bmc.keymanagement.requests.GetKeyVersionRequest
import com.oracle.bmc.keymanagement.requests.SignRequest
import com.oracle.bmc.keymanagement.requests.VerifyRequest
import id.walt.crypto.keys.Key
import id.walt.crypto.keys.KeyType
import id.walt.crypto.keys.OciKeyMeta
import id.walt.crypto.keys.jwk.JWKKey
import id.walt.crypto.utils.Base64Utils.base64UrlDecode
import id.walt.crypto.utils.Base64Utils.encodeToBase64Url
import id.walt.crypto.utils.JwsUtils.jwsAlg
import id.walt.oci.Companion.getKeyVersion
import kotlinx.serialization.Transient
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.lang.Thread.sleep

class oci(
    val id: String,

    /** public key as JWK */
    private var _publicKey: String? = null,
    private var _keyType: KeyType? = null,

) : Key() {

    @Transient
    override var keyType: KeyType
        get() = _keyType!!
        set(value) {
            _keyType = value
        }

    override val hasPrivateKey: Boolean
        get() = false

    private suspend fun retrievePublicKey(): Key {
        val getKeyRequest = GetKeyRequest.builder().keyId(id).build()
        val response = kmsManagementClient.getKey(getKeyRequest)
        val publicKey = getOCIPublicKey(kmsManagementClient, response.key.currentKeyVersion, id)
       return publicKey
    }
    val compartmentId: String = "ocid1.compartment.oc1..aaaaaaaawirugoz35riiybcxsvf7bmelqsxo3sajaav5w3i2vqowcwqrllxa"
    val vaultId: String =
        "ocid1.vault.oc1.eu-frankfurt-1.entbf645aabf2.abtheljshkb6dsuldqf324kitneb63vkz3dfd74dtqvkd5j2l2cxwyvmefeq"

    val configurationFilePath: String = "~/.oci/config"
    val profile: String = "DEFAULT"

    private val configFile: ConfigFileReader.ConfigFile = ConfigFileReader.parseDefault()

    private val provider: AuthenticationDetailsProvider =
        ConfigFileAuthenticationDetailsProvider(configFile)


    // Create KMS clients
    private var kmsVaultClient: KmsVaultClient = KmsVaultClient.builder().build(provider)

    private var vault: Vault = KmsExample.getVaultTest(kmsVaultClient, vaultId)

    var kmsManagementClient: KmsManagementClient =
        KmsManagementClient.builder().endpoint(vault.managementEndpoint).build(provider)


    private var kmsCryptoClient: KmsCryptoClient = KmsCryptoClient.builder().endpoint(vault.cryptoEndpoint).build(provider)





    // Create a key
    //   Key key = createKeyTest(kmsManagementClient, compartmentId);
//        String keyId =key.getId();
//
//        String keyVersionId = key.getCurrentKeyVersion();

    override fun toString(): String = "[OCI ${keyType.name} key @ ${vaultId}]"


    override suspend fun getKeyId(): String = getPublicKey().getKeyId()


    override suspend fun getThumbprint(): String {
        TODO("Not yet implemented")
    }

    override suspend fun exportJWK(): String = throw NotImplementedError("JWK export is not available for remote keys.")

    override suspend fun exportJWKObject(): JsonObject = Json.parseToJsonElement(_publicKey!!).jsonObject

    override suspend fun exportPEM(): String = throw NotImplementedError("PEM export is not available for remote keys.")



    override suspend fun signRaw(plaintext: ByteArray): ByteArray {

        val signDataDetails =
            SignDataDetails.builder()
                .keyId(id)
                .message(plaintext.encodeToBase64Url())
                .messageType(SignDataDetails.MessageType.Raw)
                .signingAlgorithm(SignDataDetails.SigningAlgorithm.EcdsaSha256)
                .keyVersionId(getKeyVersion(kmsManagementClient, id))
                .build()

        val signRequest =
            SignRequest.builder().signDataDetails(signDataDetails).build()
        val response = kmsCryptoClient.sign(signRequest)
        return response.signedData.signature.encodeToByteArray()
    }

    override suspend fun signJws(plaintext: ByteArray, headers: Map<String, String>): String {
        val appendedHeader = HashMap(headers).apply {
            put("alg", "ES256")
        }

        val header = Json.encodeToString(appendedHeader).encodeToByteArray().encodeToBase64Url()
        val payload = plaintext.encodeToBase64Url()

        var rawSignature = signRaw("$header.$payload".encodeToByteArray())

        val signatureBase64Url = rawSignature.encodeToBase64Url()

        return "$header.$payload.$signatureBase64Url"
    }

    override suspend fun verifyRaw(signed: ByteArray, detachedPlaintext: ByteArray?): Result<ByteArray> {

        val verifyDataDetails =
            VerifyDataDetails.builder()
                .keyId(id)
                .message(detachedPlaintext?.encodeToBase64Url())
                .signature(signed.decodeToString())
                .signingAlgorithm(VerifyDataDetails.SigningAlgorithm.EcdsaSha256)
                .build()
        val verifyRequest =
            VerifyRequest.builder().verifyDataDetails(verifyDataDetails).build()
        val response = kmsCryptoClient.verify(verifyRequest)
        return Result.success(response.verifiedData.isSignatureValid.toString().toByteArray())
    }

    override suspend fun verifyJws(signedJws: String): Result<JsonElement> {
        val parts = signedJws.split(".")
        check(parts.size == 3) { "Invalid JWT part count: ${parts.size} instead of 3" }

        val header = parts[0]
        val headers: Map<String, JsonElement> = Json.decodeFromString(header.base64UrlDecode().decodeToString())
        headers["alg"]?.let {
            val algValue = it.jsonPrimitive.content
            check(algValue == keyType.jwsAlg()) { "Invalid key algorithm for JWS: JWS has $algValue, key is ${keyType.jwsAlg()}!" }
        }

        val payload = parts[1]

        val signature = parts[2].base64UrlDecode()


        val signable = "$header.$payload".encodeToByteArray()


        return verifyRaw(signature.decodeToString().toByteArray(), signable).map {

            Json.decodeFromString(it.decodeToString())

        }
    }
    @Transient
    private var backedKey: Key? = null

    override suspend fun getPublicKey():Key = backedKey ?: when {
        _publicKey != null -> _publicKey!!.let { JWKKey.importJWK(it).getOrThrow() }
        else -> retrievePublicKey()
    }.also { newBackedKey -> backedKey = newBackedKey }


    override suspend fun getPublicKeyRepresentation():ByteArray = TODO("Not yet implemented")

    override suspend fun getMeta(): OciKeyMeta = OciKeyMeta(
        keyId = id,
        keyVersion = getKeyVersion(kmsManagementClient, id),
    )


    companion object{

        val DEFAULT_KEY_LENGTH: Int = 32
        // The KeyShape used for testing

        val TEST_KEY_SHAPE: KeyShape = KeyShape.builder().algorithm(KeyShape.Algorithm.Ecdsa).length(DEFAULT_KEY_LENGTH)
            .curveId(KeyShape.CurveId.NistP256).build()

        private fun keyTypeToOciKeyMapping(type: KeyType) = when (type) {
            KeyType.secp256r1 -> "ECDSA"
            KeyType.RSA -> "RSA"
            KeyType.secp256k1 -> throw IllegalArgumentException("Not supported: $type")
            KeyType.Ed25519 -> throw IllegalArgumentException("Not supported: $type")
        }

        private fun ociKeyToKeyTypeMapping(type: String) = when (type) {
            "ECDSA" -> KeyType.secp256r1
            "RSA" -> KeyType.RSA
            else -> throw IllegalArgumentException("Not supported: $type")
        }

         suspend fun generateKey(kmsManagementClient: KmsManagementClient, compartmentId: String ): oci {
            println("CreateKey Test")
            val createKeyDetails =
                CreateKeyDetails.builder()
                    .keyShape(TEST_KEY_SHAPE)
                    .protectionMode(CreateKeyDetails.ProtectionMode.Software)
                    .compartmentId(compartmentId)
                    .displayName("WaltKey")
                    .build()
            val createKeyRequest =
                CreateKeyRequest.builder().createKeyDetails(createKeyDetails).build()
            val response = kmsManagementClient.createKey(createKeyRequest)
println("Key created: ${response.key}")
            val keyId = response.key.id
             println("Key ID: $keyId")
             val keyVersionId = response.key.currentKeyVersion
             println("Key Version ID: $keyVersionId")
             sleep(5000)
             val publicKey = getOCIPublicKey(kmsManagementClient, keyVersionId ,keyId)

             println("Public Key: ${publicKey.exportJWK()}")
            return oci(keyId, publicKey.exportJWK(), ociKeyToKeyTypeMapping(response.key.keyShape.algorithm.toString().uppercase()))
        }


         suspend fun getOCIPublicKey(kmsManagementClient: KmsManagementClient, keyVersionId: String, keyId:String): Key {
            val getKeyRequest = GetKeyVersionRequest.builder().keyVersionId(keyVersionId).keyId(keyId).build()
            val response = kmsManagementClient.getKeyVersion(getKeyRequest)
            val publicKeyPem = response.keyVersion.publicKey
            return JWKKey.importPEM(publicKeyPem)
                .getOrThrow()
        }


        suspend fun getKeyVersion(kmsManagementClient: KmsManagementClient, keyId: String): String {
            val getKeyRequest = GetKeyRequest.builder().keyId(keyId).build()
            val response = kmsManagementClient.getKey(getKeyRequest)
            return response.key.currentKeyVersion
        }
    }

}

suspend fun main(){

    var keyId: String =
        "ocid1.key.oc1.eu-frankfurt-1.entbf645aabf2.abtheljrvxdlvr75raatjttj2dsprsk7ago7u4cjyssqd7senwqrcew5g5ha"

    var keyVersionId: String =
        "ocid1.keyversion.oc1.eu-frankfurt-1.entbf645aabf2.bciemypxlkyaa.abtheljr5ovdn5un3xuaktoqtwvzockr6b5edoy6on2p5ejfh4l6xqlotx5q"

    val compartmentId: String = "ocid1.compartment.oc1..aaaaaaaawirugoz35riiybcxsvf7bmelqsxo3sajaav5w3i2vqowcwqrllxa"
    val vaultId: String =
        "ocid1.vault.oc1.eu-frankfurt-1.entbf645aabf2.abtheljshkb6dsuldqf324kitneb63vkz3dfd74dtqvkd5j2l2cxwyvmefeq"

    val configurationFilePath: String = "~/.oci/config"
    val profile: String = "DEFAULT"

     val configFile: ConfigFileReader.ConfigFile = ConfigFileReader.parseDefault()

     val provider: AuthenticationDetailsProvider =
        ConfigFileAuthenticationDetailsProvider(configFile)


    // Create KMS clients
     var kmsVaultClient: KmsVaultClient = KmsVaultClient.builder().build(provider)

     var vault: Vault = KmsExample.getVaultTest(kmsVaultClient, vaultId)

    var kmsManagementClient: KmsManagementClient =
        KmsManagementClient.builder().endpoint(vault.managementEndpoint).build(provider)


     var kmsCryptoClient: KmsCryptoClient = KmsCryptoClient.builder().endpoint(vault.cryptoEndpoint).build(provider)


//    val key = oci.generateKey(kmsManagementClient, compartmentId)
//    println(key.getPublicKey())
//    println(key.keyType)

    val keyVersion = getKeyVersion(kmsManagementClient, "ocid1.key.oc1.eu-frankfurt-1.entbf645aabf2.abtheljrvxdlvr75raatjttj2dsprsk7ago7u4cjyssqd7senwqrcew5g5ha")
    println("Key Version: $keyVersion")


    val Testkey = oci("ocid1.key.oc1.eu-frankfurt-1.entbf645aabf2.abtheljrvxdlvr75raatjttj2dsprsk7ago7u4cjyssqd7senwqrcew5g5ha", _keyType = KeyType.secp256r1)
    println("public key: ${Testkey.getPublicKey().exportJWK()}")
    println("public key: ${Testkey.getPublicKey().exportPEM()}")

    val payload = JsonObject(
        mapOf(
            "sub" to JsonPrimitive("16bb17e0-e733-4622-9384-122bc2fc6290"),
            "iss" to JsonPrimitive("http://localhost:3000"),
            "aud" to JsonPrimitive("TOKEN"),
        )
    ).toString()
    val text = "lqfijrrwgnbizwbfxfvbubnasnltaqku"
    val sign = Testkey.signRaw(text.encodeToByteArray())



    println("Signature with TestKey: ${sign.decodeToString()}")

    val verify = Testkey.verifyRaw(sign, text.encodeToByteArray())
    println("Verify with TestKey: ${verify.getOrNull()?.decodeToString()}")


    val signJws = Testkey.signJws(
        payload.encodeToByteArray()
    )
    println("Sign JWS with TestKey: $signJws")

    val verifyJws =Testkey.verifyJws(signJws)
    println("Verify JWS with TestKey: $verifyJws")



}