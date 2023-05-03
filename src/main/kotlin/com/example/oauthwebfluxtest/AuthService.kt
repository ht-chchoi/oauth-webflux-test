package com.example.oauthwebfluxtest

import com.nimbusds.jose.JWSHeader
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.auth.verifier.*
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.id.ClientID
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.security.PublicKey

@Service
class AuthService(private val clientDetailsService: ClientDetailsService) {
    lateinit var clientAuthenticationVerifier: ClientAuthenticationVerifier<ClientDetails>

    init {

    }

    fun getToken(request: HTTPRequest):String {


        return ""
    }
}

class ReactiveClientAuthenticationVerifier<T: Any>(
    clientCredentialsSelector: ClientCredentialsSelector<T>,
    expectedAudience: MutableSet<Audience>?
) : ClientAuthenticationVerifier<T>(clientCredentialsSelector, expectedAudience) {
    fun verify(httpRequest: Mono<HTTPRequest>): Mono<Boolean> {
        return try {
            super.verify(null, null, null)
            Mono.just(true)
        } catch (e: Exception) {
            Mono.just(false)
        }
    }
}

@Component
class DatabaseClientCredentialsSelector(val clientDetailsRepository: ClientDetailsRepository): ClientCredentialsSelector<ClientDetails> {
    override fun selectClientSecrets(
        claimedClientID: ClientID?,
        authMethod: ClientAuthenticationMethod?,
        context: Context<ClientDetails>?
    ): MutableList<Secret> {
        TODO("Not yet implemented")
    }

    override fun selectPublicKeys(
        claimedClientID: ClientID?,
        authMethod: ClientAuthenticationMethod?,
        jwsHeader: JWSHeader?,
        forceRefresh: Boolean,
        context: Context<ClientDetails>?
    ): MutableList<out PublicKey> {
        TODO("Not yet implemented")
    }

}