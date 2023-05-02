package com.example.oauthwebfluxtest

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Configuration
class SecurityConfig {
    @Bean
    fun securityWebFilterChain(
        serverHttpSecurity: ServerHttpSecurity,
        authManager: AuthManager,
        authenticationConverter: AuthenticationConverter): SecurityWebFilterChain {
        val filter = AuthenticationWebFilter(authManager)
        filter.setServerAuthenticationConverter(authenticationConverter)

        serverHttpSecurity
            .authorizeExchange()
            .pathMatchers("/test").hasRole("USER")
            .pathMatchers(HttpMethod.POST, "/oauth/token").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilterAfter(filter, SecurityWebFiltersOrder.AUTHENTICATION)
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .logout().disable()

        return serverHttpSecurity.build()
    }

    @Bean
    fun userDetailsService(): MapReactiveUserDetailsService {
        return MapReactiveUserDetailsService(
            User.withDefaultPasswordEncoder()
                .username("test")
                .password("qwer")
                .roles("USER")
                .build())
    }
}

@Component
class AuthManager(private val userDetailsService: MapReactiveUserDetailsService): ReactiveAuthenticationManager {
    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        return this.userDetailsService.findByUsername(authentication.name)
            .map {
                UsernamePasswordAuthenticationToken(it.username, it.password, it.authorities)
            }
    }
}

@Component
class AuthenticationConverter: ServerAuthenticationConverter {
    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
        val token = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        return Mono.just(UsernamePasswordAuthenticationToken("test", "qwer"))
    }
}