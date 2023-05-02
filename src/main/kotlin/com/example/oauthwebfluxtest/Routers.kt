package com.example.oauthwebfluxtest

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
    fun testRoute(): RouterFunction<ServerResponse> = RouterFunctions
        .nest(
            RequestPredicates.path("/dev"),
            router {
                POST("/oauth/token") {
                    it.bodyToMono(HashMap::class.java)
                        .map { body ->
                            val a = HTTPRequest(HTTPRequest.Method.POST, it.uri())
                            a.authorization = it.headers().firstHeader(HttpHeaders.AUTHORIZATION)
                            a.query = it.formData().map {
                                it.entries.stream()
                                    .map {
                                        it.key + "=" + it.value
                                    }
                                    .collect(Collectors.joining("&"))
                            }.block()

                            ""
                        }
                        .flatMap {
                            ServerResponse.ok().bodyValue(mapOf("result" to "success"))
                        }
                }
            }
        )
}