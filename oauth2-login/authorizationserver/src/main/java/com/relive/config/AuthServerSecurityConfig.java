package com.relive.config;

import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthServerSecurityConfig {
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .cors(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/userInfo", "/oauth2/authorize**", "/login**", "/debug/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth2/authorize**", "/login**", "/debug/**").permitAll()
                        .requestMatchers("/userInfo").hasAuthority("SCOPE_profile")
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation().migrateSession()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/login", "/userInfo"))
                .formLogin(Customizer.withDefaults())
                .cors(Customizer.withDefaults());

        return http.build();
    }
}
