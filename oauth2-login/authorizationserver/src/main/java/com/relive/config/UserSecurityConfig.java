package com.relive.config;

/**
 * Configuration class for user security settings.
 * This class defines beans for user authentication and password encoding.
 */
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserSecurityConfig {

        // Create a user with default password encoder, username, password and roles
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
        // Return an InMemoryUserDetailsManager with the configured user
                .roles("USER", "ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    /**
     * Creates and configures a PasswordEncoder bean.
     * This bean provides a delegating password encoder that supports multiple encoding formats.
     *
     * @return PasswordEncoder instance with support for multiple encoding formats
     */
    }

        // Create and return a delegating password encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}