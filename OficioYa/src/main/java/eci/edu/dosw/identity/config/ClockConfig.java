package eci.edu.dosw.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 
 * ClockConfig: we use this class because when the app starts will send a object with the real clock to other class
 * thereby fulfilling the inversion of control
 */
@Configuration
public class ClockConfig {

    
    /*@Bean indicates that a method produces a bean to be managed by the Spring container. 
    It registers the returned object in the application context,
     making it available for dependency injection wherever needed. */
    @Bean 
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}