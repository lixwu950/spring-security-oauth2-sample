package com.relive.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * @author: ReLive
 * @date: 2022/7/8 3:37 下午
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin(from -> {
                    from.defaultSuccessUrl("/home");
                })
                .oauth2Login(Customizer.withDefaults())
                .csrf().disable();
        return http.build();
    }

    @Bean
    DefaultJsonOAuth2UserService defaultJsonOAuth2UserService() {
        return new DefaultJsonOAuth2UserService();
    }

    @Bean
    GrantedAuthoritiesMapper userAuthoritiesMapper() {
        //Role mapping relationship, authorization server ADMIN role corresponds to client OPERATION role.
        Map<String, String> roleMapping = new HashMap<>();
        roleMapping.put("ROLE_ADMIN", "ROLE_OPERATION");
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority) authority;
                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
                    List<String> role = (List) userAttributes.get("role");
                    role.stream().map(roleMapping::get)
                            .filter(StringUtils::hasText)
                            .map(SimpleGrantedAuthority::new)
                            .forEach(mappedAuthorities::add);
                }
            });
            return mappedAuthorities;
        };
    }

    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withUsername("admin")
                .password("{noop}password")
                .roles("SYSTEM")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public CommandLineRunner checkOAuth2Config(ClientRegistrationRepository clientRegistrations) {
        return args -> {
            System.out.println("=== Available OAuth2 Clients ===");

            if (clientRegistrations instanceof InMemoryClientRegistrationRepository) {
                Iterable<ClientRegistration> registrations =
                        (InMemoryClientRegistrationRepository) clientRegistrations;

                Iterator<ClientRegistration> iterator = registrations.iterator();
                if (!iterator.hasNext()) {
                    System.out.println("No OAuth2 client registrations configured!");
                    return;
                }

                while (iterator.hasNext()) {
                    ClientRegistration registration = iterator.next();
                    System.out.println("Registration ID: " + registration.getRegistrationId());
                    System.out.println("Client ID: " + registration.getClientId());
                    System.out.println("Client Secret: " + (registration.getClientSecret() != null ? "***" : "null"));
                    System.out.println("Redirect URI: " + registration.getRedirectUri());
                    System.out.println("Authorization Grant Type: " + registration.getAuthorizationGrantType());
                    System.out.println("Scopes: " + registration.getScopes());
                    System.out.println("Provider: " + registration.getProviderDetails());
                    System.out.println("---");
                }
            } else {
                System.out.println("Unexpected ClientRegistrationRepository type: " +
                        clientRegistrations.getClass().getName());
            }
        };
    }
}
