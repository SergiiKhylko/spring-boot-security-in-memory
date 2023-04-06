package com.ajkko.spring.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig  {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> {
                            try {
                                authz
                                        .antMatchers("/admin").hasRole("admin")
                                        .antMatchers("/user").hasAnyRole("admin", "user")
                                        .antMatchers("/hello").permitAll()
                                        .and().formLogin();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        UserDetails admin = User
                .withUsername("administrator")
                .password(passwordEncoder.encode("pass"))
                .roles("admin")
                .build();

        UserDetails sergiiUser = User
                .withUsername("Sergii")
                .password(passwordEncoder.encode("pass"))
                .roles("user")
                .build();

        userDetailsManager.createUser(admin);
        userDetailsManager.createUser(sergiiUser);
        return userDetailsManager;
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

}
