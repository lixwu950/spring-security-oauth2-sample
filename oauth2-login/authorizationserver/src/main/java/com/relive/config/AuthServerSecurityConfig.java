package com.relive.config;

import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthServerSecurityConfig {
    @Bean
    public CookieSameSiteSupplier applicationSameSiteSupplier() {
        // HTTP 环境必须使用 Lax
        return CookieSameSiteSupplier.ofLax();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/oauth2/authorize**", "/login**", "/debug/**", "/userInfo").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation().migrateSession()  // 确保会话连续性
                );
        return http.build();
    }
}
