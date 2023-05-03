package com.example.oauthwebfluxtest

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.ServletUtils
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.web.reactive.function.server.*
import java.util.stream.Collectors

@Configuration
class RouterTest {
    @Bean
    fun testRoute(authService: AuthService): RouterFunction<ServerResponse> = RouterFunctions
        .nest(
            RequestPredicates.path("/dev"),
            router {
                POST("/oauth/token") {
                    it.formData().map {form ->
                        val a = HTTPRequest(HTTPRequest.Method.POST, it.uri())
                        a.authorization = it.headers().firstHeader(HttpHeaders.AUTHORIZATION)
                        a.query = form.entries.stream()
                            .map {
                                it.key + "=" + it.value[0]
                            }
                            .collect(Collectors.joining("&"))
                        a
                    }.doOnNext { httpReq ->
                        println(authService.getToken(httpReq))
                        println()
                    }.flatMap {
                        ServerResponse.ok().bodyValue(mapOf("result" to "success"))
                    }

                }
            }
        )
}