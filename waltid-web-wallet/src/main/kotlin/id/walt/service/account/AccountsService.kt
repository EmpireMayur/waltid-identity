package id.walt.service.account

import id.walt.db.models.*
import id.walt.db.models.todo.AccountIssuers
import id.walt.db.models.todo.Issuers
import id.walt.service.WalletServiceManager
import id.walt.web.controllers.generateToken
import id.walt.web.model.AccountRequest
import id.walt.web.model.AddressAccountRequest
import id.walt.web.model.EmailAccountRequest
import kotlinx.datetime.toKotlinInstant
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.uuid.UUID
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction

object AccountsService {

    suspend fun register(tenant: String? = null, request: AccountRequest): Result<RegistrationResult> = when (request) {
        is EmailAccountRequest -> EmailAccountStrategy.register(tenant, request)
        is AddressAccountRequest -> Web3WalletAccountStrategy.register(tenant, request)
    }.onSuccess { registrationResult ->
        val registeredUserId = registrationResult.id

        val createdInitialWalletId = transaction {
            WalletServiceManager.createWallet(tenant, registeredUserId)
        }

        val walletService = WalletServiceManager.getWalletService(tenant, registeredUserId, createdInitialWalletId)

        // Add default data:
        val createdDid = walletService.createDid("key", mapOf("alias" to JsonPrimitive("Onboarding")))
        walletService.setDefault(createdDid)

        transaction {
            queryDefaultIssuer("walt.id")?.let { defaultIssuer ->
                AccountIssuers.insert {
                    it[AccountIssuers.tenant] = tenant
                    it[accountId] = registeredUserId
                    it[issuer] = defaultIssuer
                }
            }
        }

    }.onFailure {
        throw IllegalStateException("Could not register user", it)
    }

    private fun queryDefaultIssuer(name: String) =
        Issuers.select(Issuers.name eq name).singleOrNull()?.let {
            it[Issuers.id]
        }?.value

    suspend fun authenticate(tenant: String?, request: AccountRequest): Result<AuthenticationResult> = runCatching {
        when (request) {
            is EmailAccountRequest -> EmailAccountStrategy.authenticate(tenant, request)
            is AddressAccountRequest -> Web3WalletAccountStrategy.authenticate(tenant, request)
        }
    }.fold(onSuccess = {
        Result.success(
            AuthenticationResult(
                id = it.id,
                username = it.username,
                token = generateToken()
            )
        )
    },
        onFailure = { Result.failure(it) })

    fun getAccountWalletMappings(tenant: String?, account: UUID) =
        AccountWalletListing(account, wallets =
        transaction {
            AccountWalletMappings.innerJoin(Wallets)
                .select { (AccountWalletMappings.tenant eq tenant) and (AccountWalletMappings.accountId eq account) }
                .map {
                    AccountWalletListing.WalletListing(
                        id = it[AccountWalletMappings.wallet].value,
                        name = it[Wallets.name],
                        createdOn = it[Wallets.createdOn].toKotlinInstant(),
                        addedOn = it[AccountWalletMappings.addedOn].toKotlinInstant(),
                        permission = it[AccountWalletMappings.permissions]
                    )
                }
        }
        )


    fun hasAccountEmail(tenant: String?, email: String) = transaction { Accounts.select { (Accounts.tenant eq tenant) and (Accounts.email eq email) }.count() > 0 }
    fun hasAccountWeb3WalletAddress(address: String) =
        transaction {
            Accounts.innerJoin(Web3Wallets)
                .select { Web3Wallets.address eq address }
                .count() > 0
        }

    fun getAccountByWeb3WalletAddress(address: String) =
        transaction {
            Accounts.innerJoin(Web3Wallets)
                .select { Web3Wallets.address eq address }
                .map { Account(it) }
        }

    fun getNameFor(account: UUID) = Accounts.select { Accounts.id eq account }.single()[Accounts.email]
}

@Serializable
data class AuthenticationResult(
    val id: UUID,
    val username: String,
    val token: String,
)

@Serializable
data class RegistrationResult(
    val id: UUID,
)

data class AuthenticatedUser(
    val id: UUID,
    val username: String
)

interface AccountStrategy<in T : AccountRequest> {
    fun register(tenant: String?, request: T): Result<RegistrationResult>
    suspend fun authenticate(tenant: String?, request: T): AuthenticatedUser
}