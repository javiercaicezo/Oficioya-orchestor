package eci.edu.dosw.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * PasswordEncoderConfig: this class we use to codify (hashing) the password of a user
 * using the BCrypt that automatically add salt to the password to make it more secureally 
 * and if two users have the same password will not have the same hash
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

