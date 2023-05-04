package com.example.oauthwebfluxtest

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.data.jpa.repository.config.EnableJpaAuditing
import org.springframework.data.jpa.repository.config.EnableJpaRepositories

@SpringBootApplication
@EnableJpaRepositories(basePackages = ["com.example.oauthwebfluxtest"])
@EnableJpaAuditing()
class OauthWebfluxTestApplication

fun main(args: Array<String>) {
    runApplication<OauthWebfluxTestApplication>(*args)
}
