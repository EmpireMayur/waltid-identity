import id.walt.crypto.keys.KeyType
import id.walt.crypto.keys.OCIKey
import id.walt.crypto.keys.OCIKeyConfig
import io.ktor.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class OCIKeyTest {

  val Config =
      OCIKeyConfig(
          "ocid1.tenancy.oc1..aaaaaaaaiijfupfvsqwqwgupzdy5yclfzcccmie4ktp2wlgslftv5j7xpk6q",
          "ocid1.user.oc1..aaaaaaaaxjkkfjqxdqk7ldfjrxjmacmbi7sci73rbfiwpioehikavpbtqx5q",
          "bb:d4:4b:0c:c8:3a:49:15:7f:87:55:d5:2b:7e:dd:bc",
          "ens3g6m3aabyo-management.kms.eu-frankfurt-1.oraclecloud.com",
          "ocid1.tenancy.oc1..aaaaaaaaiijfupfvsqwqwgupzdy5yclfzcccmie4ktp2wlgslftv5j7xpk6q/ocid1.user.oc1..aaaaaaaaxjkkfjqxdqk7ldfjrxjmacmbi7sci73rbfiwpioehikavpbtqx5q/bb:d4:4b:0c:c8:3a:49:15:7f:87:55:d5:2b:7e:dd:bc",
          "ocid1.key.oc1.eu-frankfurt-1.ens3g6m3aabyo.abtheljr3eq62dewopgedq3nwubek4art77q4erzx7s6hv55e3zcuvp46epa",
          "ens3g6m3aabyo-crypto.kms.eu-frankfurt-1.oraclecloud.com",
      )
  internal val payload =
      JsonObject(
          mapOf(
              "sub" to JsonPrimitive("16bb17e0-e733-4622-9384-122bc2fc6290"),
              "iss" to JsonPrimitive("http://localhost:3000"),
              "aud" to JsonPrimitive("TOKEN"),
          ))

  val keyVersion =
      "ocid1.keyversion.oc1.eu-frankfurt-1.ens3g6m3aabyo.bcmcmw3bjsyaa.abtheljr6nftkbcmvcqlitj6cujg5uflhbafdyumf576qrk55s7z7mvp2aeq"

  val public_key =
      "-----BEGIN PUBLIC KEY-----\n" +
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlMvjcHDwXHDhSu7BCxtP\n" +
          "UnhH4z+rRZnlVkcQegs24hsUdfQrYXmhQoWzAGpF4SDWP09p1Ia6CcY4IOGr5uOr\n" +
          "MhS0aoLPr5XIvZQdMiL4zw+8cfotovziW2XfITN9jKNWgVeuiFoqYm154aj7vtza\n" +
          "Y9uYhW0e8gn0xlhn2VCUMxH4MDHkOU1QL7aYqY+yxMJHkpO/EwF0TErKyxpbrUL6\n" +
          "JCG4hlJYznx48z8mgU0/ezfbx2JdOkLvYmKKJGETsKd3QaBkJrbm6nqZLE1/TQ8Q\n" +
          "Xx/EZNg4kJzoLhq5D/Oi0AIHszpPiIVE6Rpx51UPIyG1Cu6vdmldZhRrgrtQPwP0\n" +
          "zQIDAQAB\n" +
          "-----END PUBLIC KEY-----\n"
  val key = OCIKey(Config, null, KeyType.RSA)

  @Test
  fun testOCI() = runTest {
    println("Testing sign & verify RAW (payload: ${payload})...")
    ociTestSignRaw()

    println("Testing sign & verify JWS (payload: ${payload})...")
    ociTestSignJws()

    println("Testing Get Public Key ...")
    ociTestgetPublicKey()
  }

  private suspend fun ociTestSignRaw() {
    val signing = key.signRaw(payload.toString().encodeToByteArray()) as String
    val verification =
        key.verifyRaw(signing.decodeBase64Bytes(), payload.toString().encodeToByteArray())
    println(verification)
  }

  private suspend fun ociTestSignJws() {
    val signing = key.signJws(payload.toString().encodeToByteArray())
    val verification = key.verifyJws(signing)
    assertTrue(verification.isSuccess)
    assertEquals(payload, verification.getOrThrow())
  }

  private suspend fun ociTestgetPublicKey() {
    val key =
        OCIKey.getOCIPublicKey(
            Config.OCIDKeyID, Config.keyId, Config.managementEndpoint, keyVersion)
    assertEquals(public_key, key)
  }
}