package id.walt.webwallet.service

import id.walt.crypto.keys.Key
import id.walt.crypto.keys.KeySerialization
import id.walt.crypto.keys.KeyType
import id.walt.crypto.keys.LocalKey
import id.walt.did.dids.DidService
import id.walt.did.dids.registrar.LocalRegistrar
import id.walt.did.dids.registrar.dids.DidCheqdCreateOptions
import id.walt.did.dids.registrar.dids.DidJwkCreateOptions
import id.walt.did.dids.registrar.dids.DidKeyCreateOptions
import id.walt.did.dids.registrar.dids.DidWebCreateOptions
import id.walt.did.dids.resolver.LocalResolver
import id.walt.did.utils.EnumUtils.enumValueIgnoreCase
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.errors.AuthorizationError
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.OpenIDClientConfig
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.oid4vc.responses.AuthorizationErrorCode
import id.walt.webwallet.db.models.WalletCategoryData
import id.walt.webwallet.db.models.WalletCredential
import id.walt.webwallet.db.models.WalletOperationHistories
import id.walt.webwallet.db.models.WalletOperationHistory
import id.walt.webwallet.service.category.CategoryService
import id.walt.webwallet.service.credentials.CredentialFilterObject
import id.walt.webwallet.service.credentials.CredentialsService
import id.walt.webwallet.service.dids.DidsService
import id.walt.webwallet.service.dto.LinkedWalletDataTransferObject
import id.walt.webwallet.service.dto.WalletDataTransferObject
import id.walt.webwallet.service.events.*
import id.walt.webwallet.service.exchange.IssuanceService
import id.walt.webwallet.service.keys.KeysService
import id.walt.webwallet.service.keys.SingleKeyResponse
import id.walt.webwallet.service.oidc4vc.TestCredentialWallet
import id.walt.webwallet.service.report.ReportRequestParameter
import id.walt.webwallet.service.report.ReportService
import id.walt.webwallet.service.settings.SettingsService
import id.walt.webwallet.service.settings.WalletSetting
import id.walt.webwallet.usecase.event.EventUseCase
import id.walt.webwallet.web.controllers.PresentationRequestParameter
import id.walt.webwallet.web.parameter.CredentialRequestParameter
import io.ktor.client.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.toJavaInstant
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlinx.uuid.UUID
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import kotlin.collections.set
import kotlin.time.Duration.Companion.seconds

class SSIKit2WalletService(
    tenant: String,
    accountId: UUID,
    walletId: UUID,
    private val categoryService: CategoryService,
    private val settingsService: SettingsService,
    private val eventUseCase: EventUseCase,
    private val http: HttpClient
) : WalletService(tenant, accountId, walletId) {
    private val logger = LoggerFactory.getLogger(this::class.java)
    private val credentialService = CredentialsService()
    private val eventService = EventService()
    private val credentialReportsService = ReportService.Credentials(credentialService, eventService)

    companion object {
        init {
            runBlocking {
                DidService.apply {
                    registerResolver(LocalResolver())
                    updateResolversForMethods()
                    registerRegistrar(LocalRegistrar())
                    updateRegistrarsForMethods()
                }
            }
        }
        val testCIClientConfig = OpenIDClientConfig("test-client", null, redirectUri = "http://blank")
        private val credentialWallets = HashMap<String, TestCredentialWallet>()
        fun getCredentialWallet(did: String) = credentialWallets.getOrPut(did) {
            TestCredentialWallet(
                CredentialWalletConfig("http://blank"), did
            )
        }
    }

    override fun listCredentials(filter: CredentialFilterObject): List<WalletCredential> =
        credentialService.list(walletId, filter)

    override suspend fun listRawCredentials(): List<String> =
        credentialService.list(walletId, CredentialFilterObject.default).map {
            it.document
        }

    override suspend fun deleteCredential(id: String, permanent: Boolean) = let {
        credentialService.get(walletId, id)?.run {
            eventUseCase.log(
                action = EventType.Credential.Delete,
                originator = "wallet",
                tenant = tenant,
                accountId = accountId,
                walletId = walletId,
                data = eventUseCase.credentialEventData(this, null),
                credentialId = this.id
            )
        }
        credentialService.delete(walletId, id, permanent)
    }

    override suspend fun restoreCredential(id: String): WalletCredential =
        credentialService.restore(walletId, id) ?: error("Credential not found: $id")

    override suspend fun getCredential(credentialId: String): WalletCredential =
        credentialService.get(walletId, credentialId)
            ?: throw IllegalArgumentException("WalletCredential not found for credentialId: $credentialId")

    override suspend fun attachCategory(credentialId: String, categories: List<String>): Boolean =
        credentialService.categoryService.add(
            wallet = walletId, credentialId = credentialId, category = categories.toTypedArray()
        ) == categories.size

    override suspend fun detachCategory(credentialId: String, categories: List<String>): Boolean =
        credentialService.categoryService.delete(walletId, credentialId, *categories.toTypedArray()) > 0

    override suspend fun renameCategory(oldName: String, newName: String): Boolean =
        categoryService.rename(walletId, oldName, newName) > 0

    override suspend fun acceptCredential(parameter: CredentialRequestParameter): Boolean =
        credentialService.get(walletId, parameter.credentialId)?.takeIf { it.deletedOn == null }?.let {
            credentialService.setPending(walletId, parameter.credentialId, false) > 0
        } ?: error("Credential not found: ${parameter.credentialId}")

    override suspend fun rejectCredential(parameter: CredentialRequestParameter): Boolean =
        credentialService.delete(walletId, parameter.credentialId, true)

    override fun matchCredentialsByPresentationDefinition(presentationDefinition: PresentationDefinition): List<WalletCredential> {
        val credentialList = listCredentials(CredentialFilterObject.default)
        
        logger.debug("WalletCredential list is: {}", credentialList.map { it.parsedDocument?.get("type")!!.jsonArray })

        data class TypeFilter(val path: String, val type: String? = null, val pattern: String)

        val filters = presentationDefinition.inputDescriptors.mapNotNull { inputDescriptor ->
            inputDescriptor.constraints?.fields?.filter { field -> field.path.any { path -> path.contains("type") } }
                ?.map {
                    val path = it.path.first().removePrefix("$.")
                    val filterType = it.filter?.get("type")?.jsonPrimitive?.content
                    val filterPattern = it.filter?.get("pattern")?.jsonPrimitive?.content
                        ?: throw IllegalArgumentException("No filter pattern in presentation definition constraint")

                    TypeFilter(path, filterType, filterPattern)
                }?.plus(inputDescriptor.schema?.map { schema ->
                    TypeFilter("type", "string", schema.uri)
                } ?: listOf())
        }

        logger.debug("Using filters: {}", filters)

        val matchedCredentials = when {
            filters.isNotEmpty() -> credentialList.filter { credential ->
                filters.any { fields ->
                    fields.all { typeFilter ->
                        val credField = credential.parsedDocument!![typeFilter.path] ?: return@all false

                        when (credField) {
                            is JsonPrimitive -> credField.jsonPrimitive.content == typeFilter.pattern
                            is JsonArray -> credField.jsonArray.last().jsonPrimitive.content == typeFilter.pattern
                            else -> false
                        }
                    }
                }
            }

            else -> credentialList.filter { cred ->
                presentationDefinition.inputDescriptors.any { desc -> desc.name == cred.parsedDocument?.get("type")?.jsonArray?.last()?.jsonPrimitive?.content }
            }
        }


        logger.debug("Matched credentials: {}", matchedCredentials)

        return matchedCredentials.ifEmpty { credentialList }
    }
    
    
    /* SIOP */
    @Serializable
    data class PresentationResponse(
        val vp_token: String,
        val presentation_submission: String,
        val id_token: String?,
        val state: String?,
        val fulfilled: Boolean,
        val rp_response: String?
    )

    @Serializable
    data class SIOPv2Response(
        val vp_token: String, val presentation_submission: String, val id_token: String?, val state: String?
    )

    data class PresentationError(
        override val message: String, val redirectUri: String?
    ) : IllegalArgumentException(message)


    /**
     * @return redirect uri
     */
    override suspend fun usePresentationRequest(parameter: PresentationRequestParameter): Result<String?> {
        val credentialWallet = getCredentialWallet(parameter.did)

        val authReq =
            AuthorizationRequest.fromHttpParametersAuto(parseQueryString(Url(parameter.request).encodedQuery).toMap())
        logger.debug("Auth req: {}", authReq)

        logger.debug("USING PRESENTATION REQUEST, SELECTED CREDENTIALS: {}", parameter.selectedCredentials)

        SessionAttributes.HACK_outsideMappedSelectedCredentialsPerSession[authReq.state + authReq.presentationDefinition] =
            parameter.selectedCredentials
        if (parameter.disclosures != null) {
            SessionAttributes.HACK_outsideMappedSelectedDisclosuresPerSession[authReq.state + authReq.presentationDefinition] =
                parameter.disclosures
        }

        val presentationSession =
            credentialWallet.initializeAuthorization(authReq, 60.seconds, parameter.selectedCredentials.toSet())
        logger.debug("Initialized authorization (VPPresentationSession): {}", presentationSession)

        logger.debug("Resolved presentation definition: ${presentationSession.authorizationRequest!!.presentationDefinition!!.toJSONString()}")

        val tokenResponse = credentialWallet.processImplicitFlowAuthorization(presentationSession.authorizationRequest)
        val resp = this.http.submitForm(presentationSession.authorizationRequest.responseUri
            ?: presentationSession.authorizationRequest.redirectUri ?: throw AuthorizationError(
                presentationSession.authorizationRequest,
                AuthorizationErrorCode.invalid_request,
                "No response_uri or redirect_uri found on authorization request"
            ), parameters {
            tokenResponse.toHttpParameters().forEach { entry ->
                entry.value.forEach { append(entry.key, it) }
            }
        })
        val httpResponseBody = runCatching { resp.bodyAsText() }.getOrNull()
        val isResponseRedirectUrl = httpResponseBody != null && httpResponseBody.take(10).lowercase().let {
            @Suppress("HttpUrlsUsage") it.startsWith("http://") || it.startsWith("https://")
        }
        logger.debug("HTTP Response: {}, body: {}", resp, httpResponseBody)
        parameter.selectedCredentials.forEach {
            credentialService.get(walletId, it)?.run {
                eventUseCase.log(
                    action = EventType.Credential.Present,
                    originator = presentationSession.presentationDefinition?.name ?: EventDataNotAvailable,
                    tenant = tenant,
                    accountId = accountId,
                    walletId = walletId,
                    data = eventUseCase.credentialEventData(this, null),
                    credentialId = this.id,
                    note = parameter.note,
                )
            }
        }

        return if (resp.status.isSuccess()) {
            Result.success(if (isResponseRedirectUrl) httpResponseBody else null)
        } else {
            if (isResponseRedirectUrl) {
                Result.failure(
                    PresentationError(
                        message = "Presentation failed - redirecting to error page", redirectUri = httpResponseBody
                    )
                )
            } else {
                logger.debug("Response body: $httpResponseBody")
                Result.failure(
                    PresentationError(
                        message = if (httpResponseBody != null) "Presentation failed:\n $httpResponseBody" else "Presentation failed",
                        redirectUri = ""
                    )
                )
            }
        }
    }

    override suspend fun resolvePresentationRequest(request: String): String {
        val credentialWallet = getAnyCredentialWallet()

        return Url(request).protocolWithAuthority.plus("?")
            .plus(credentialWallet.parsePresentationRequest(request).toHttpQueryString())
    }

    private fun getAnyCredentialWallet() =
        credentialWallets.values.firstOrNull() ?: getCredentialWallet("did:test:test")
    
        override suspend fun useOfferRequest(
        offer: String, did: String, requireUserInput: Boolean
    ): List<WalletCredential> {
        val addableCredentials =
            IssuanceService.useOfferRequest(offer, getCredentialWallet(did), testCIClientConfig.clientID).map {
                WalletCredential(
                    wallet = walletId,
                    id = it.id,
                    document = it.document,
                    disclosures = it.disclosures,
                    addedOn = Clock.System.now(),
                    manifest = it.manifest,
                    deletedOn = null,
                    pending = requireUserInput,
                ).also { credential ->
                    eventUseCase.log(
                        action = EventType.Credential.Receive,
                        originator = "", //parsedOfferReq.credentialOffer!!.credentialIssuer,
                        tenant = tenant,
                        accountId = accountId,
                        walletId = walletId,
                        data = eventUseCase.credentialEventData(credential = credential, type = it.type),
                        credentialId = credential.id,
                    )
                }
            }
        credentialService.add(
            wallet = walletId, credentials = addableCredentials.toTypedArray()
        )
        return addableCredentials
    }

    override suspend fun resolveCredentialOffer(offerRequest: CredentialOfferRequest): CredentialOffer {
        return getAnyCredentialWallet().resolveCredentialOffer(offerRequest)
    }

    /* DIDs */

    override suspend fun createDid(method: String, args: Map<String, JsonPrimitive>): String {
        val keyId = args["keyId"]?.content?.takeIf { it.isNotEmpty() } ?: generateKey(KeyType.Ed25519.name)
        val key = getKey(keyId)
        val options = getDidOptions(method, args)
        val result = DidService.registerByKey(method, key, options)
        DidsService.add(
            wallet = walletId,
            did = result.did,
            document = result.didDocument.toString(),
            alias = args["alias"]?.content,
            keyId = keyId
        )
        eventUseCase.log(
            action = EventType.Did.Create,
            originator = "wallet",
            tenant = tenant,
            accountId = accountId,
            walletId = walletId,
            data = eventUseCase.didEventData(result.did, result.didDocument)
        )
        return result.did
    }

    override suspend fun listDids() = transaction { DidsService.list(walletId) }

    override suspend fun loadDid(did: String): JsonObject = DidsService.get(walletId, did)?.let {
        Json.parseToJsonElement(it.document).jsonObject
    } ?: throw IllegalArgumentException("Did not found: $did for account: $walletId")


    override suspend fun deleteDid(did: String): Boolean {
        DidsService.get(walletId, did).also {
            eventUseCase.log(
                action = EventType.Did.Delete,
                originator = "wallet",
                tenant = tenant,
                accountId = accountId,
                walletId = walletId,
                data = eventUseCase.didEventData(
                    did = it?.did ?: did, document = it?.document ?: EventDataNotAvailable
                ),
            )
        }
        return DidsService.delete(walletId, did)
    }

    override suspend fun setDefault(did: String) = DidsService.makeDidDefault(walletId, did)

    /* Keys */

    private suspend fun getKey(keyId: String) = KeysService.get(walletId, keyId)?.let {
        KeySerialization.deserializeKey(it.document)
            .getOrElse { throw IllegalArgumentException("Could not deserialize resolved key: ${it.message}", it) }
    } ?: throw IllegalArgumentException("Key not found: $keyId")

    suspend fun getKeyByDid(did: String): Key = DidService.resolveToKey(did).fold(onSuccess = {
        getKey(it.getKeyId())
    }, onFailure = {
        throw it
    })

    override suspend fun exportKey(alias: String, format: String, private: Boolean): String = let {
        runCatching {
            getKey(alias).also {
                eventUseCase.log(
                    action = EventType.Key.Export,
                    originator = "wallet",
                    tenant = tenant,
                    accountId = accountId,
                    walletId = walletId,
                    data = eventUseCase.keyEventData(it, EventDataNotAvailable)
                )
            }
        }.fold(onSuccess = {
            when (format.lowercase()) {
                "jwk" -> it.exportJWK()
                "pem" -> it.exportPEM()
                else -> throw IllegalArgumentException("Unknown format: $format")
            }
        }, onFailure = {
            throw it
        })
    }

    override suspend fun loadKey(alias: String): JsonObject = getKey(alias).exportJWKObject()

    override suspend fun listKeys(): List<SingleKeyResponse> = KeysService.list(walletId).map {
        val key = KeySerialization.deserializeKey(it.document).getOrThrow()

        SingleKeyResponse(
            keyId = SingleKeyResponse.KeyId(it.keyId),
            algorithm = key.keyType.name,
            cryptoProvider = key.toString(),
            keyPair = JsonObject(emptyMap()),
            keysetHandle = JsonNull
        )
    }

    override suspend fun generateKey(type: String): String =
        LocalKey.generate(KeyType.valueOf(type)).let { createdKey ->
            eventUseCase.log(
                action = EventType.Key.Create,
                originator = "wallet",
                tenant = tenant,
                accountId = accountId,
                walletId = walletId,
                data = eventUseCase.keyEventData(createdKey, "local")
            )
            KeysService.add(walletId, createdKey.getKeyId(), KeySerialization.serializeKey(createdKey))
            createdKey.getKeyId()
        }

    override suspend fun importKey(jwkOrPem: String): String {
        val type = when {
            jwkOrPem.lines().first().contains("BEGIN ") -> "pem"
            else -> "jwk"
        }

        val keyResult = when (type) {
            "pem" -> LocalKey.importPEM(jwkOrPem)
            "jwk" -> LocalKey.importJWK(jwkOrPem)
            else -> throw IllegalArgumentException("Unknown key type: $type")
        }

        if (keyResult.isFailure) {
            throw IllegalArgumentException("Could not import key as: $type; error message: " + keyResult.exceptionOrNull()?.message)
        }

        val key = keyResult.getOrThrow()
        val keyId = key.getKeyId()
        eventUseCase.log(
            action = EventType.Key.Import,
            originator = "wallet",
            tenant = tenant,
            accountId = accountId,
            walletId = walletId,
            data = eventUseCase.keyEventData(key, EventDataNotAvailable)
        )
        KeysService.add(walletId, keyId, KeySerialization.serializeKey(key))
        return keyId
    }

    override suspend fun deleteKey(alias: String): Boolean = runCatching {
        KeysService.get(walletId, alias)?.let { Json.parseToJsonElement(it.document) }?.run {
            eventUseCase.log(
                action = EventType.Key.Delete,
                originator = "wallet",
                tenant = tenant,
                accountId = accountId,
                walletId = walletId,
                data = eventUseCase.keyEventData(
                    id = this.jsonObject["jwk"]?.jsonObject?.get("kid")?.jsonPrimitive?.content
                        ?: EventDataNotAvailable,
                    algorithm = this.jsonObject["jwk"]?.jsonObject?.get("kty")?.jsonPrimitive?.content
                        ?: EventDataNotAvailable,
                    kmsType = EventDataNotAvailable
                )
            )
        }
    }.let {
        KeysService.delete(walletId, alias)
    }

    override fun getHistory(limit: Int, offset: Long): List<WalletOperationHistory> =
        WalletOperationHistories.selectAll().where { WalletOperationHistories.wallet eq walletId }
            .orderBy(WalletOperationHistories.timestamp).limit(10).map { row ->
                WalletOperationHistory(row)
            }

    override suspend fun addOperationHistory(operationHistory: WalletOperationHistory) {
        transaction {
            WalletOperationHistories.insert {
                it[tenant] = operationHistory.tenant
                it[accountId] = operationHistory.account
                it[wallet] = operationHistory.wallet
                it[timestamp] = operationHistory.timestamp.toJavaInstant()
                it[operation] = operationHistory.operation
                it[data] = Json.encodeToString(operationHistory.data)
            }
        }
    }

    override fun filterEventLog(filter: EventLogFilter): EventLogFilterResult = runCatching {
        val startingAfterItemIndex = filter.startingAfter?.toLongOrNull()?.takeIf { it >= 0 } ?: -1L
        val pageSize = filter.limit
        val count = eventUseCase.count(walletId, filter.data)
        val offset = startingAfterItemIndex + 1
        val events = eventUseCase.get(
            EventUseCase.EventFilterParameter(
                accountId = accountId,
                walletId = walletId,
                offset = offset,
                logFilter = filter,
            )
        )
        EventLogFilterDataResult(
            items = events,
            count = events.size,
            currentStartingAfter = computeCurrentStartingAfter(startingAfterItemIndex),
            nextStartingAfter = computeNextStartingAfter(startingAfterItemIndex, pageSize, count)
        )
    }.fold(onSuccess = {
        it
    }, onFailure = {
        EventLogFilterErrorResult(reason = it.localizedMessage)
    })

    override suspend fun linkWallet(wallet: WalletDataTransferObject): LinkedWalletDataTransferObject =
        Web3WalletService.link(tenant, walletId, wallet)

    override suspend fun unlinkWallet(wallet: UUID) = Web3WalletService.unlink(tenant, walletId, wallet)

    override suspend fun getLinkedWallets(): List<LinkedWalletDataTransferObject> =
        Web3WalletService.getLinked(tenant, walletId)

    override suspend fun connectWallet(walletId: UUID) = Web3WalletService.connect(tenant, this.walletId, walletId)

    override suspend fun disconnectWallet(wallet: UUID) = Web3WalletService.disconnect(tenant, walletId, wallet)

    override fun getCredentialsByIds(credentialIds: List<String>): List<WalletCredential> {
        // todo: select by SQL
        return listCredentials(CredentialFilterObject.default).filter { it.id in credentialIds }
    }

    override suspend fun listCategories(): List<WalletCategoryData> = categoryService.list(walletId)

    override suspend fun addCategory(name: String): Boolean = categoryService.add(walletId, name) == 1

    override suspend fun deleteCategory(name: String): Boolean = categoryService.delete(walletId, name) == 1
    override suspend fun getFrequentCredentials(parameter: ReportRequestParameter): List<WalletCredential> =
        credentialReportsService.frequent(parameter)

    override suspend fun getSettings(): WalletSetting = settingsService.get(walletId)

    override suspend fun setSettings(settings: JsonObject): Boolean = settingsService.set(walletId, settings) > 0

    private fun getDidOptions(method: String, args: Map<String, JsonPrimitive>) = when (method.lowercase()) {
        "key" -> DidKeyCreateOptions(args["key"]?.let { enumValueIgnoreCase<KeyType>(it.content) } ?: KeyType.Ed25519,
            args["useJwkJcsPub"]?.let { it.content.toBoolean() } ?: false)

        "jwk" -> DidJwkCreateOptions()
        "web" -> DidWebCreateOptions(domain = args["domain"]?.content ?: "", path = args["path"]?.content ?: "")
        "cheqd" -> DidCheqdCreateOptions(
            network = args["network"]?.content ?: "testnet",
        )

        else -> throw IllegalArgumentException("Did method not supported: $method")
    }

    //TODO: move to related entity
    private fun computeCurrentStartingAfter(afterItemIndex: Long): String? = let {
        afterItemIndex.takeIf { it >= 0 }?.toString()
    }

    //TODO: move to related entity
    private fun computeNextStartingAfter(afterItemIndex: Long, pageSize: Int, count: Long): String? = let {
        val itemIndex = afterItemIndex + pageSize
        itemIndex.takeIf { it < count }?.toString()
    }
}

