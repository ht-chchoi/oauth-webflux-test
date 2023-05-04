package com.example.oauthwebfluxtest

import com.example.oauthwebfluxtest.auth.AuthService
import com.nimbusds.oauth2.sdk.AccessTokenResponse
import com.nimbusds.oauth2.sdk.TokenResponse
import com.nimbusds.oauth2.sdk.http.HTTPRequest
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
            RequestPredicates.all(),
            router {
                POST("/oauth/token") {
                    it.formData().map {form ->
                        authService.mapToHTTPRequest(it, form, null)
                    }.map { httpReq ->
                        authService.getToken(httpReq)
                    }.flatMap {
                        ServerResponse.ok().bodyValue(mapOf("result" to "success"))
                    }

                }
            }
        )
}