package com.example.oauthwebfluxtest.auth

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.util.*
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id

@Entity
class ClientDetails {
    @Id
    var id: Long? = null
    lateinit var clientId: String
    lateinit var clientSecret: String
    lateinit var clientAuthenticationMethod: String
    lateinit var scopes: String
    lateinit var authorities: String
    lateinit var grantTypes: String
    var accessTokenValidity: Int = 0
    var refreshTokenValidity: Int = 0

    @CreatedDate
    var creDate: LocalDateTime? = null
    @LastModifiedDate
    var modDate: LocalDateTime? = null
}

@Repository
interface ClientDetailsRepository: JpaRepository<ClientDetails, Long> {
    fun findByClientIdAndClientAuthenticationMethod(clientId: String, clientAuthenticationMethod: String): ClientDetails?
}