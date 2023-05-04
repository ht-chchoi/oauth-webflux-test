package com.example.oauthwebfluxtest.auth

import com.nimbusds.jose.JWSHeader
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.auth.verifier.*
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.id.ClientID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import java.security.PublicKey
import java.time.LocalDateTime
import java.util.*
import javax.persistence.Entity
import javax.persistence.EntityListeners
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.MappedSuperclass

@EntityListeners(AuditingEntityListener::class)
@Entity
class ClientDetails {
    constructor()

    constructor(
        clientId: String,
        clientSecret: String,
        clientAuthenticationMethod: String,
        scopes: String,
        authorities: String,
        grantTypes: String,
        accessTokenValidity: Int,
        refreshTokenValidity: Int
    ) {
        this.clientId = clientId
        this.clientSecret = clientSecret
        this.clientAuthenticationMethod = clientAuthenticationMethod
        this.scopes = scopes
        this.authorities = authorities
        this.grantTypes = grantTypes
        this.accessTokenValidity = accessTokenValidity
        this.refreshTokenValidity = refreshTokenValidity
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null
    lateinit var clientId: String
    lateinit var clientSecret: String
    lateinit var clientAuthenticationMethod: String
    lateinit var scopes: String
    lateinit var authorities: String
    lateinit var grantTypes: String
    var accessTokenValidity: Int = 0
    var refreshTokenValidity: Int = 0

    @CreatedDate
    var creDate: LocalDateTime? = null
    @LastModifiedDate
    var modDate: LocalDateTime? = null
}

@Repository
interface ClientDetailsRepository: JpaRepository<ClientDetails, Long> {
    fun findByClientIdAndClientAuthenticationMethod(clientId: String, clientAuthenticationMethod: String): ClientDetails?
}

@Service
class ClientService(
    private val clientAuthenticationVerifierEncodeSupport: ClientAuthenticationVerifierEncodeSupport
) {
    fun isValidClient(clientAuthentication: ClientAuthentication, hints: MutableSet<Hint>?, context: Context<ClientDetails>?): Boolean {
        return try {
            this.clientAuthenticationVerifierEncodeSupport.verify(clientAuthentication, hints, context)
            true
        } catch (e: Exception) {
            false
        }
    }
}

@Component
class ClientAuthenticationVerifierEncodeSupport(
    private val passwordEncoder: PasswordEncoder,
    databaseClientCredentialsSelector: DatabaseClientCredentialsSelector,
): ClientAuthenticationVerifier<ClientDetails>(
    databaseClientCredentialsSelector, setOf(Audience("TO_BE_CREATE"))
) {

    override fun verify(clientAuth: ClientAuthentication, hints: MutableSet<Hint>?, context: Context<ClientDetails>?) {
        when (clientAuth) {
            is PlainClientSecret -> this.verifyPlainClientSecret(clientAuth, context)
            else -> super.verify(clientAuth, hints, context)
        }
    }

    private fun verifyPlainClientSecret(clientAuth: ClientAuthentication, context: Context<ClientDetails>?) {
        // Secret From DB
        val secretCandidates = clientCredentialsSelector
            .selectClientSecrets(clientAuth.clientID, clientAuth.method, context)
            .filterNotNull()
            .ifEmpty {
                throw InvalidClientException.NO_REGISTERED_SECRET
            }

        val plainAuth = clientAuth as PlainClientSecret

        for (candidate in secretCandidates) {
            if (passwordEncoder.matches(plainAuth.clientSecret.value, candidate.value)) {
                return
            }
        }

        throw InvalidClientException.BAD_SECRET
    }
}


@Component
class DatabaseClientCredentialsSelector(
    val clientDetailsRepository: ClientDetailsRepository
): ClientCredentialsSelector<ClientDetails> {
    override fun selectClientSecrets(
        claimedClientID: ClientID,
        authMethod: ClientAuthenticationMethod,
        context: Context<ClientDetails>?
    ): MutableList<Secret> {
        return when (val result = this.clientDetailsRepository.findByClientIdAndClientAuthenticationMethod(claimedClientID.value, authMethod.value)) {
            null -> mutableListOf()
            else -> mutableListOf(Secret(result.clientSecret))
        }
    }

    override fun selectPublicKeys(
        claimedClientID: ClientID?,
        authMethod: ClientAuthenticationMethod?,
        jwsHeader: JWSHeader?,
        forceRefresh: Boolean,
        context: Context<ClientDetails>?
    ): MutableList<out PublicKey> {
        return mutableListOf()
    }
}