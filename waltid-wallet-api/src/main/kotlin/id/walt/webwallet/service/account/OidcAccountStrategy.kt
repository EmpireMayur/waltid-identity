package id.walt.webwallet.service.account

import id.walt.webwallet.config.ConfigManager
import id.walt.webwallet.config.OidcConfiguration
import id.walt.webwallet.db.models.Accounts
import id.walt.webwallet.db.models.OidcLogins
import id.walt.webwallet.utils.JwkUtils.verifyToken
import id.walt.webwallet.web.controllers.getUserInfo
import id.walt.webwallet.web.model.OidcAccountRequest
import kotlinx.datetime.Clock
import kotlinx.datetime.toJavaInstant
import kotlinx.uuid.UUID
import kotlinx.uuid.generateUUID
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction

object OidcAccountStrategy : PasswordlessAccountStrategy<OidcAccountRequest>() {
    override suspend fun register(tenant: String, request: OidcAccountRequest): Result<RegistrationResult> {
        val jwt = verifyToken(request.token)
        val config = ConfigManager.getConfig<OidcConfiguration>()

        require(!(AccountsService.hasAccountOidcId(jwt.subject))) { "Account already exists with OIDC id: ${request.token}" }

        val userInfo = when (config.providerName == "auth0") {
            true -> getUserInfo(request.token)
            false -> jwt.claims
        }


        val createdAccountId = transaction {
            val accountId = Accounts.insert {
                it[Accounts.tenant] = tenant
                it[id] = UUID.generateUUID()
                it[name] = userInfo["name"].toString()
                it[email] = userInfo["email"].toString()
                it[createdOn] = Clock.System.now().toJavaInstant()
            }[Accounts.id]

            OidcLogins.insert {
                it[OidcLogins.tenant] = tenant
                it[OidcLogins.accountId] = accountId
                it[oidcId] = jwt.subject
            }

            accountId
        }

        return Result.success(RegistrationResult(createdAccountId))
    }


    override suspend fun authenticate(tenant: String, request: OidcAccountRequest): AuthenticatedUser {
        val jwt = verifyToken(request.token)

        val registeredUserId = if (AccountsService.hasAccountOidcId(jwt.subject)) {
            AccountsService.getAccountByOidcId(jwt.subject)!!.id
        } else {
            AccountsService.register(tenant, request).getOrThrow().id
        }
        // TODO: change id to wallet-id (also in the frontend)
        return UsernameAuthenticatedUser(registeredUserId, jwt.subject)
    }
}
