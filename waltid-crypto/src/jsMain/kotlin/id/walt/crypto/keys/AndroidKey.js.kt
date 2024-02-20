package id.walt.crypto.keys

import kotlinx.serialization.json.JsonObject

actual class AndroidKey : Key() {

    /*
    /**
     * Encrypts as JWE: Encrypts a message using this public key (with the algorithm this key is based on)
     * @exception IllegalArgumentException when this is not a private key, when this algorithm does not support encryption
     * @param plaintext data to be encrypted
     * @return encrypted (JWE)
     */
    override suspend fun encrypt(plaintext: ByteArray): String

    /**
     * Decrypts JWE: Decrypts an encrypted message using this private key
     * @param encrypted encrypted
     * @return Result wrapping the plaintext; Result failure when the decryption fails
     */
    override suspend fun decrypt(encrypted: ByteArray): Result<ByteArray>
     */
    actual override suspend fun getKeyId(): String {
        TODO("Not yet implemented")
    }

    actual override suspend fun getThumbprint(): String {
        TODO("Not yet implemented")
    }

    actual override suspend fun exportJWK(): String {
        TODO("Not yet implemented")
    }

    actual override suspend fun exportJWKObject(): JsonObject {
        TODO("Not yet implemented")
    }

    actual override suspend fun exportPEM(): String {
        TODO("Not yet implemented")
    }

    /**
     * Signs as a JWS: Signs a message using this private key (with the algorithm this key is based on)
     * @exception IllegalArgumentException when this is not a private key
     * @param plaintext data to be signed
     * @return signed (JWS)
     */
    actual override suspend fun signRaw(plaintext: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual override suspend fun signJws(plaintext: ByteArray, headers: Map<String, String>): String {
        TODO("Not yet implemented")
    }

    /**
     * Verifies JWS: Verifies a signed message using this public key
     * @param signed signed
     * @return Result wrapping the plaintext; Result failure when the signature fails
     */
    actual override suspend fun verifyRaw(signed: ByteArray, detachedPlaintext: ByteArray?): Result<ByteArray> {
        TODO("Not yet implemented")
    }

    actual override suspend fun verifyJws(signedJws: String): Result<JsonObject> {
        TODO("Not yet implemented")
    }

    actual override suspend fun getPublicKey(): AndroidKey {
        TODO("Not yet implemented")
    }

    actual override suspend fun getPublicKeyRepresentation(): ByteArray {
        TODO("Not yet implemented")
    }

    override val keyType: KeyType
        get() = TODO("Not yet implemented")

    actual override val hasPrivateKey: Boolean
        get() = TODO("Not yet implemented")

    actual companion object : AndroidKeyCreator {
        actual override suspend fun generate(
            type: KeyType,
            metadata: LocalKeyMetadata
        ): AndroidKey {
            TODO("Not yet implemented")
        }

    }


}