package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "SELECT user_id, pw, active FROM members WHERE user_id = ?"
        );

        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "SELECT user_id, role FROM roles WHERE user_id = ?"
        );

        return jdbcUserDetailsManager;
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests(config -> config
                .requestMatchers(HttpMethod.GET, "/api/employees")
                .hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.GET, "/api/employees/**")
                .hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.POST, "/api/employees")
                .hasRole("MANAGER")
                .requestMatchers(HttpMethod.PUT, "/api/employees")
                .hasRole("MANAGER")
                .requestMatchers(HttpMethod.DELETE, "/api/employees/**")
                .hasRole("ADMIN")
        );

        // use basic authentication

        httpSecurity.httpBasic();

        // disable CSRF, in general not required for stateless REST APIs use POST, PUT, DELETE, and/or PATCH
        httpSecurity.csrf().disable();

        return httpSecurity.build();
    }

    //    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails raki = User.builder()
//                .username("raki")
//                .password("{noop}test123")
//                .roles("EMPLOYEE")
//                .build();
//
//        UserDetails allan = User.builder()
//                .username("allan")
//                .password("{noop}test123")
//                .roles("EMPLOYEE", "MANAGER")
//                .build();
//
//        UserDetails elora = User.builder()
//                .username("elora")
//                .password("{noop}test123")
//                .roles("EMPLOYEE", "MANAGER", "ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(raki, allan, elora);
//    }

}
