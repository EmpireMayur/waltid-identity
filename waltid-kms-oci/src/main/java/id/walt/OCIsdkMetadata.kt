package id.walt

import kotlinx.serialization.Serializable

@Serializable
data class OCIsdkMetadata(
    val vaultId: String,
    val compartmentId: String,

)
