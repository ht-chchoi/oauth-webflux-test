package com.example.oauthwebfluxtest

import io.r2dbc.spi.ConnectionFactories
import io.r2dbc.spi.ConnectionFactory
import io.r2dbc.spi.ConnectionFactoryOptions
import io.r2dbc.spi.Option
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing
import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories

@Configuration
@EnableR2dbcRepositories
@EnableR2dbcAuditing
class R2dbcMainDBConfig {
    @Value("\${r2dbc.main.host}")
    val host: String = ""

    @Value("\${r2dbc.main.port}")
    val port: Int = -1

    @Value("\${r2dbc.main.username}")
    val username: String = ""

    @Value("\${r2dbc.main.password}")
    val password: String = ""

    @Bean
    fun mainConnectionFactory(): ConnectionFactory = ConnectionFactories
        .get(
            ConnectionFactoryOptions.builder()
            .option(ConnectionFactoryOptions.SSL, true)
            .option(ConnectionFactoryOptions.DRIVER, "pool")
            .option(ConnectionFactoryOptions.PROTOCOL, "mariadb")
            .option(ConnectionFactoryOptions.HOST, host)
            .option(ConnectionFactoryOptions.PORT, port)
            .option(ConnectionFactoryOptions.USER, username)
            .option(ConnectionFactoryOptions.PASSWORD, password)
            .option(ConnectionFactoryOptions.DATABASE, "main")
            .option(Option.valueOf("initialSize"), 5)
            .option(Option.valueOf("maxSize"), 20)
            .option(Option.valueOf("validationQuery"), "select 1+1")
            .build())
}