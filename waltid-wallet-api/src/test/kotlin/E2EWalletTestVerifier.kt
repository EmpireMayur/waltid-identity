import PresentationDefinitionFixtures.Companion.presentationDefinitionExample1
import PresentationDefinitionFixtures.Companion.presentationDefinitionExample2
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import id.walt.issuer.base.config.OIDCIssuerServiceConfig
import id.walt.issuer.issuerModule
import id.walt.verifier.base.config.OIDCVerifierServiceConfig
import id.walt.verifier.VerifierApiExamples.maxExample
import id.walt.verifier.VerifierApiExamples.minimal
import id.walt.verifier.VerifierApiExamples.vcVpIndividualPolicies
import id.walt.verifier.VerifierApiExamples.vpGlobalVcPolicies
import id.walt.verifier.VerifierApiExamples.vpPolicies
import id.walt.verifier.verifierModule
import id.walt.webwallet.config.DatasourceConfiguration
import id.walt.webwallet.db.Db
import id.walt.webwallet.utils.WalletHttpClients
import id.walt.webwallet.webWalletModule
import id.walt.webwallet.webWalletSetup
import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.testing.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.test.*
import kotlin.time.Duration.Companion.seconds
import id.walt.issuer.base.config.ConfigManager as IssuerConfigManager
import id.walt.webwallet.config.ConfigManager as WalletConfigManager
import id.walt.webwallet.config.WebConfig as WalletWebConfig
import id.walt.verifier.base.config.ConfigManager as VerifierConfigManager

open class E2EWalletTestVerifier : E2EWalletTestBase() {
    
    private lateinit var localWalletClient: HttpClient
    private var localWalletUrl: String = ""
    private var localIssuerUrl: String = ""
    private var localVerifierUrl: String = ""
    
    
    private fun ApplicationTestBuilder.newClient(token: String? = null) = createClient {
        install(ContentNegotiation) {
            json()
        }
        install(Logging) {
            logger = Logger.SIMPLE
            level = LogLevel.ALL
        }
        followRedirects = false
        defaultRequest {
            contentType(ContentType.Application.Json)
            if (token != null) {
                header("Authorization", "Bearer $token")
            }
        }
    }
    
    private suspend fun ApplicationTestBuilder.runApplication() = run {
        println("Running in ${Path(".").absolutePathString()}")
        localWalletClient = newClient()
        
        WalletHttpClients.defaultMethod = {
            newClient()
        }
        setupTestWebWallet()
        
        println("Setup issuer...")
        setupTestIssuer()
        
        println("Setup verifier...")
        setupTestVerifier()
        
        println("Starting application...")
        application {
            webWalletModule()
            issuerModule(withPlugins = false)
            verifierModule(withPlugins = false)
        }
        getUserToken()
        localWalletClient = newClient(token)
        
        // list all wallets for this user (sets wallet id)
        listAllWallets()
    }
    
    private fun setupTestWebWallet() {
        // TODO moving this into init{} causes error 400 status code in issuance test
        Db.start()
    }
    
    private fun setupTestIssuer() {
        IssuerConfigManager.preloadConfig("issuer-service", OIDCIssuerServiceConfig("http://localhost"))
        
        IssuerConfigManager.loadConfigs(emptyArray())
    }
    
    open fun setupTestVerifier() {
        VerifierConfigManager.preloadConfig("verifier-service", OIDCVerifierServiceConfig("http://localhost"))
        
        VerifierConfigManager.loadConfigs(emptyArray())
    }
    
    // Verifier Tests
    @Test
    fun e2eTestPolicyList() = testApplication {
        runApplication()
        val list: JsonObject = testPolicyList()
        
        assertNotEquals(0, list.size)
        list.keys.forEach {
            println("$it -> ${list[it]?.jsonPrimitive?.content}")
        }
    }
    
    @Test
    fun e2eTestVerify() = testApplication {
        runApplication()
        var url = testVerifyCredential(minimal)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("minimal presentation definition: verify Url = $url")
        
        url = testVerifyCredential(vpPolicies)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("vp policy definition :verify Url = $url")
        
        url = testVerifyCredential(vpGlobalVcPolicies)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("vp policy definition with global Vcs:verify Url = $url")
        
        url = testVerifyCredential(vcVpIndividualPolicies)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("vp policy definition with specific Vc credential policies:verify Url = $url")
        
        url = testVerifyCredential(maxExample)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("vp policy definition explicit presentation definition:verify Url = $url")
    }
    
    @Test
    fun e2eTestPresentationSession() = testApplication {
        runApplication()
        val url = testVerifyCredential(minimal)
        val startStr = "state="
        val endStr = "&presentation"
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        
        val start = url.indexOf(startStr) + startStr.length
        val end = url.indexOf(endStr)
        
        // extract 'state' from URL
        val state = url.substring(start, end)
        println("session id (state) = $state")
        testSession(state)
        
        // TODO use this Url to present credentials (filtered according to presentation definition)
    }
    
    @Test
    fun e2eTestPresentationRequest() = testApplication {
        runApplication()
        val url = testVerifyCredential(minimal)
        assertTrue(url.startsWith("openid4vp://authorize?response_type=vp_token"))
        println("verify Url = $url")

        val parsedRequest = testResolvePresentationRequest(url)
        println("Parsed Request = $parsedRequest")
    }
    
    @Test
    fun e2eTestMatchCredentialsForPresentationDefinition() = testApplication {
        runApplication()
        var matchedCredentials = testPresentationDefinition(presentationDefinitionExample1)
        assertEquals(1, matchedCredentials.size)
        
        // if the match fails, SSI Wallet kit returns full list of credentials
        // this is intentional
        val totalNumCredentials = listCredentials().size
        
        assertNotEquals(totalNumCredentials, 0)
        
        matchedCredentials = testPresentationDefinition(presentationDefinitionExample2)
        
        assertEquals(totalNumCredentials, matchedCredentials.size)
    }
    
    @Test
    fun e2eTestFullPresentationUseCase() = testApplication {
        runTest(timeout = 60.seconds) {
            runApplication()
            deleteAllCredentials()
            issueNewCredential()

            // full e2e run of verification endpoints

            // 1. call to /verify in the Verifier API
            val url = testVerifyCredential(minimal)
            println("Verify Url = $url")

            // 2. resolve presentation request with URI from 1)

            val parsedRequest = testResolvePresentationRequest(url)
            println("Parsed Request = $parsedRequest")

            // 3. Match credentials of the required type, e.g., OpenBadgeCredential
            val matchedCredentials = testPresentationDefinition(presentationDefinitionExample1)
            assertEquals(1, matchedCredentials.size)

            val id = matchedCredentials[0].jsonObject["id"]?.jsonPrimitive?.content
            assertNotNull(id)

            // 4. Use output of 2) and 3) to create presentation to return to relying party
            val json = """
            {
                "presentationRequest": "$parsedRequest",
                "selectedCredentials": [
                    "$id"
                ]
            }
            """.trimIndent()
            testUsePresentationRequest(json)
        }
    }
    override var walletClient: HttpClient
        get() = localWalletClient
        set(value) {
            localWalletClient = value
        }
    
    override var walletUrl: String
        get() = localWalletUrl
        set(value) {
            localWalletUrl = value
        }
    
    override var issuerUrl: String
        get() = localIssuerUrl
        set(value) {
            localIssuerUrl = value
        }
    
    override var verifierUrl: String
        get() = localVerifierUrl
        set(value) {
            localVerifierUrl = value
        }
}