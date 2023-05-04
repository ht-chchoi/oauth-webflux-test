package com.example.oauthwebfluxtest.auth

import com.nimbusds.common.contenttype.ContentType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.auth.verifier.*
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.util.CollectionUtils
import com.nimbusds.oauth2.sdk.util.ListUtils
import com.nimbusds.oauth2.sdk.util.URLUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import java.net.URL
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*
import java.util.stream.Collectors

@Service
class AuthService(
    val clientDetailsRepository: ClientDetailsRepository,
    val clientAuthenticationVerifier: ClientAuthenticationVerifier<ClientDetails>) {


    fun <T> mapToHTTPRequest(serverRequest: ServerRequest, formData: MultiValueMap<String, String>?, body: T?): HTTPRequest {
        val method = HTTPRequest.Method.valueOf(serverRequest.methodName().uppercase())

        val url: URL = serverRequest.uri().toURL()

        val request = HTTPRequest(method, url)

        val reqContentType = serverRequest.headers().contentType()
            .orElseThrow{ IllegalArgumentException("no Content-Type header value") }

        try {
            request.setContentType(reqContentType.toString())
        } catch (e: ParseException) {
            throw IllegalArgumentException("Invalid Content-Type header value: " + e.message, e)
        }

        serverRequest.headers().asHttpHeaders().entries
            .filter { it.value != null }
            .forEach {
                request.setHeader(it.key, *it.value.toTypedArray<String>())
            }

        if (method == HTTPRequest.Method.GET || method == HTTPRequest.Method.DELETE) {
            request.query = serverRequest.queryParams()
                .map { "${it.key}=${it.value}" }
                .stream()
                .collect(Collectors.joining("&"))
        } else if (method == HTTPRequest.Method.POST || method == HTTPRequest.Method.PUT) {
            if (ContentType.APPLICATION_URLENCODED.matches(request.entityContentType)) {
                if (formData != null) {
                    request.query = URLUtils.serializeParameters(formData.entries.stream()
                        .collect(Collectors.toMap(Map.Entry<String, List<String>>::key, Map.Entry<String, List<String>>::value)))
                }
            } else {
                request.query = body.toString()
            }
        }

        // Extract validated client X.509 if we have mutual TLS
        val cert = extractClientX509Certificate(serverRequest)
        if (cert != null) {
            request.clientX509Certificate = cert
            request.clientX509CertificateSubjectDN = if (cert.subjectDN != null) cert.subjectDN.name else null

            // The root DN cannot be reliably set for a CA-signed
            // client cert from a servlet request, unless self-issued
            if (X509CertificateUtils.hasMatchingIssuerAndSubject(cert)) {
                request.clientX509CertificateRootDN = if (cert.issuerDN != null) cert.issuerDN.name else null
            }
        }

        // Extract client IP address
        serverRequest.remoteAddress().ifPresent {
            request.clientIPAddress = it.toString()
        }

        return request
    }

    fun extractClientX509Certificate(serverRequest: ServerRequest): X509Certificate? {
        val optionalCerts = serverRequest.attribute("javax.servlet.request.X509Certificate")
        return if (optionalCerts.isEmpty) {
            null
        } else {
            (optionalCerts.get() as Array<*>)[0] as X509Certificate
        }
    }

    fun getToken(request: HTTPRequest):String {
        val tokenRequest = TokenRequest.parse(request)
        val clientAuth = ClientAuthentication.parse(request)
        clientAuthenticationVerifier.verify(clientAuth, null, null)
//        val tokens = Tokens.parse(JSONObject())
//        val a= this.clientDetailsRepository.findByClientId(clientAuth.clientID.value)


        return ""
    }
}

@Configuration
class AuthConfig {
    @Bean
    fun clientAuthenticationVerifier(
        databaseClientCredentialsSelector: DatabaseClientCredentialsSelector
    ): ClientAuthenticationVerifier<ClientDetails> = ClientAuthenticationVerifier(
        databaseClientCredentialsSelector, setOf(Audience("TO_BE_CREATE"))
    )
}

@Component
class ClientAuthenticationVerifierEncodeSupport(
    private val passwordEncoder: PasswordEncoder,
    databaseClientCredentialsSelector: DatabaseClientCredentialsSelector
): ClientAuthenticationVerifier<ClientDetails>(
    databaseClientCredentialsSelector, setOf(Audience("TO_BE_CREATE"))
) {
    override fun verify(clientAuth: ClientAuthentication?, hints: MutableSet<Hint>?, context: Context<ClientDetails>?) {
        when (clientAuth) {
            is PlainClientSecret -> this.verifyPlainClientSecret()
            else -> super.verify(clientAuth, hints, context)
        }
    }

    private fun verifyPlainClientSecret(clientAuth: ClientAuthentication, context: Context<ClientDetails>?) {
        val secretCandidates = clientCredentialsSelector
            .selectClientSecrets(clientAuth.clientID, clientAuth.method, context)
            .filterNotNull()
            .ifEmpty {
                throw InvalidClientException.NO_REGISTERED_SECRET
            }

        val plainAuth = clientAuth as PlainClientSecret

        for (candidate in secretCandidates) {

            // Constant time, SHA-256 based, unless overridden
            if (candidate == plainAuth.clientSecret) {
                return  // success
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