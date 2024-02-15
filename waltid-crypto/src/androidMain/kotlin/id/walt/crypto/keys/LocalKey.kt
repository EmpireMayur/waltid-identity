package id.walt.crypto.keys

import android.util.Base64
import id.walt.crypto.keys.AndroidLocalKeyGenerator.PUBLIC_KEY_ALIAS_PREFIX
import kotlinx.serialization.json.JsonObject
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.util.UUID

actual class LocalKey actual constructor(jwk: String?) : Key() {

    override val keyType: KeyType
        get() = internalKeyType

    private lateinit var internalKeyType: KeyType

    actual override val hasPrivateKey: Boolean
        get() {
            return (keyStore.getKey(internalKeyId, null) as PrivateKey?) != null
        }

    private val keyStore = KeyStore.getInstance(AndroidLocalKeyGenerator.ANDROID_KEYSTORE).apply {
        load(null)
    }

    private lateinit var internalKeyId: String

    constructor(keyAlias: KeyAlias, keyType: KeyType) : this(null) {
        internalKeyId = keyAlias.alias
        internalKeyType = keyType
        println("Initialised instance of LocalKey {keyId: '$internalKeyId'}")
    }

    actual override suspend fun getKeyId(): String = internalKeyId

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

    actual override suspend fun signRaw(plaintext: ByteArray): ByteArray {
        check(hasPrivateKey) { "No private key is attached to this key!" }

        val privateKey: PrivateKey = keyStore.getKey(internalKeyId, null) as PrivateKey

        val signature: ByteArray? = getSignature().run {
            initSign(privateKey)
            update(plaintext)
            sign()
        }

        println("Raw message signed with signature {signature: '${Base64.encodeToString(signature, Base64.DEFAULT)}'}")
        println("Raw message signed - {raw: '${plaintext.decodeToString()}'}")

        return Base64.encodeToString(signature, Base64.DEFAULT).toByteArray()
    }

    actual override suspend fun signJws(plaintext: ByteArray, headers: Map<String, String>): String {
        TODO("Not yet implemented")
    }

    actual override suspend fun verifyRaw(signed: ByteArray, detachedPlaintext: ByteArray?): Result<ByteArray> {
        val certificate: Certificate? = keyStore.getCertificate(internalKeyId)

        return if (certificate != null) {
            val signature: ByteArray = Base64.decode(signed.decodeToString(), Base64.DEFAULT)

            println("signature to verify- ${signed.decodeToString()}")
            println("plaintext - ${detachedPlaintext!!.decodeToString()}")

            val isValid: Boolean = getSignature().run {
                initVerify(certificate)
                update(detachedPlaintext)
                verify(signature)
            }

            return if (isValid) {
                Result.success(detachedPlaintext)
            } else {
                Result.failure(Exception("Signature is not valid"))
            }

        } else {
            Result.failure(Exception("Certificate not found in KeyStore"))
        }
    }

    actual override suspend fun verifyJws(signedJws: String): Result<JsonObject> {
        TODO("Not yet implemented")
    }

    actual override suspend fun getPublicKey(): LocalKey {
        return if (hasPrivateKey) {
            val keyPair = keyStore.getEntry(internalKeyId, null) as? KeyStore.PrivateKeyEntry
            checkNotNull(keyPair) { "This LocalKey instance does not have a KeyPair!" }

            val id = "$PUBLIC_KEY_ALIAS_PREFIX${UUID.randomUUID()}"
            keyStore.setCertificateEntry(id, keyPair.certificate)
            LocalKey(KeyAlias(id), keyType)
        } else this
    }

    actual override suspend fun getPublicKeyRepresentation(): ByteArray {
        return if (hasPrivateKey) {
            val keyPair = keyStore.getEntry(internalKeyId, null) as? KeyStore.PrivateKeyEntry
            checkNotNull(keyPair) { "This LocalKey instance does not have a KeyPair!" }
            keyPair.certificate.publicKey.encoded
        } else {
            keyStore.getCertificate(internalKeyId).publicKey.encoded
        }
    }

    private fun getSignature(): Signature = when (keyType) {
        KeyType.secp256k1 -> Signature.getInstance("SHA256withECDSA", "BC")//Legacy SunEC curve disabled
        KeyType.secp256r1 -> Signature.getInstance("SHA256withECDSA")
        KeyType.Ed25519 -> Signature.getInstance("Ed25519")
        KeyType.RSA -> Signature.getInstance("SHA256withRSA")
    }

    actual companion object : LocalKeyCreator {
        actual override suspend fun generate(
            type: KeyType, metadata: LocalKeyMetadata
        ): LocalKey = AndroidLocalKeyGenerator.generate(type, metadata)

        actual override suspend fun importRawPublicKey(
            type: KeyType, rawPublicKey: ByteArray, metadata: LocalKeyMetadata
        ): Key {
            TODO("Not yet implemented")
        }

        actual override suspend fun importJWK(jwk: String): Result<LocalKey> {
            TODO("Not yet implemented")
        }

        actual override suspend fun importPEM(pem: String): Result<LocalKey> {
            TODO("Not yet implemented")
        }

    }
}