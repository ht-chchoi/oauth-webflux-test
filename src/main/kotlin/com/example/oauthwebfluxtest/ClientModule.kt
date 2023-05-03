package com.example.oauthwebfluxtest

import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class ClientDetailsService(val clientDetailsRepository: ClientDetailsRepository) {
    val passwordEncoder: PasswordEncoder = BCryptPasswordEncoder(4)



    fun encode(value: String): String {
        return this.passwordEncoder.encode(value)
    }
}

data class ClientDetails(
    @Id
    val id: Long? = null,
    var clientId: String,
    var clientSecret: String,
    var scopes: String,
    var authorities: String,
    var grantTypes: String,
    var accessTokenValidity: Int,
    var refreshTokenValidity: Int,
    @CreatedDate
    var creDate: LocalDateTime? = null,
    @LastModifiedDate
    var modDate: LocalDateTime? = null
) {

}

interface ClientDetailsRepository: ReactiveCrudRepository<ClientDetails, Long>