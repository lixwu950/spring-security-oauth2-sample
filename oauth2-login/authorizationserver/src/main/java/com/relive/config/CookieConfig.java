package com.relive.config;

import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Configures Cross-Origin Resource Sharing (CORS) settings for the application.
 * This bean defines which origins, methods, headers are allowed for cross-domain requests.
 *
 * @return CorsConfigurationSource configured CORS settings
 */
import java.util.List;

    // Create a new CorsConfiguration object
@Configuration
    // Set the allowed origins (frontend addresses)
public class CookieConfig {
    // Set the allowed HTTP methods
    // Set the allowed headers - using '*' allows all headers
    @Bean
    // Enable credentials support (cookies/sessions)
    public CorsConfigurationSource corsConfigurationSource() {
    // Create a source to register the CORS configuration
        CorsConfiguration configuration = new CorsConfiguration();
    // Register the CORS configuration for all endpoints ("/**")
        configuration.setAllowedOrigins(List.of("http://127.0.0.1:8070")); // 前端地址
    // Return the configured CORS source
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true); // 如果使用 cookie/session
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


}
