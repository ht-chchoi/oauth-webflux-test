package com.example.oauthwebfluxtest

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.server.*
import reactor.core.publisher.Mono
import java.security.Principal

import org.springframework.web.reactive.function.server.RequestPredicates.*

//@RestController
class TestController {
    @GetMapping("/test")
    fun getTest(principal: Mono<Principal>): Mono<Any> {

        return principal.map {
            mapOf("result" to "success", "name" to it.name)
        }
    }
}

