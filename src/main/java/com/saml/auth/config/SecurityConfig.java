package com.saml.auth.config;

import java.util.Arrays;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

import jakarta.servlet.http.HttpServletResponse;

import java.util.function.Consumer;

@Configuration
public class SecurityConfig {


   
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http, 
                                               RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) 
                                               throws Exception {
    try {
        http
            .csrf(csrf -> csrf.disable()) // ✅ Disabling CSRF (only if necessary)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/saml2/service-provider-metadata/**", "/actuator/**").permitAll() // ✅ Allowing unauthenticated metadata access
                .anyRequest().authenticated()
            )
            .saml2Login(withDefaults()) // ✅ Ensure correct import
            .saml2Logout(withDefaults()); // ✅ Ensure correct import

        return http.build();
    } catch (Exception e) {
        // ✅ Proper Logging for Debugging
        throw new RuntimeException("Error configuring security: " + e.getMessage(), e);
    }
}

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        try {
            RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation("https://login.theflyexpress.com/realms/qa-theflyexpress/protocol/saml/descriptor")
                .entityId("https://login.theflyexpress.com/realms/qa-theflyexpress")
                .registrationId("keycloak")
                .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/keycloak")
                .build();
            
            System.out.println("✅ Loaded SAML Registration: " + registration.getRegistrationId());
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        } catch (Exception e) {
            System.err.println("❌ Error loading SAML metadata: " + e.getMessage());
            throw new RuntimeException("SAML metadata load failed!", e);
        }
    }

   
}
