package id.walt.ebsi.eth
import id.walt.crypto.keys.Key
import kotlinx.serialization.Serializable

@Serializable
data class UnsignedTransaction(
  val from: String,
  val to: String,
  val data: String,
  val nonce: String,
  val chainId: String,
  val gasLimit: String,
  val gasPrice: String,
  val value: String
) {
  fun sign(key: Key): SignedTransaction {
    TODO()
  }
}

@Serializable
data class SignedTransaction(val r: String, val s: String, val v: String, val signedRawTransaction: String)