package com.example.springauth0.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/user").hasAnyAuthority("Customer", "Admin")
                .requestMatchers(HttpMethod.POST, "/user").hasAnyAuthority("Admin")
                .requestMatchers(HttpMethod.GET, "/health").permitAll()
                .anyRequest().denyAll()
        );

        http.oauth2ResourceServer().jwt().decoder(this.jwtDecoder()).jwtAuthenticationConverter(
                jwt -> new JwtAuthenticationToken(jwt,
                        jwt.getClaimAsStringList("http://localhost:8080/roles")
                                .stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList())
                )
        );
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // 作成したApplicationのDomainをissuerに設定する
        // issuerの最後に「/」を入れないとエラーになる
        return JwtDecoders.fromIssuerLocation("https://dev-vy8siz1eicf5nds5.jp.auth0.com/");
    }

}