package com.in28minutes.springboot.myfirstwebapp.security;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.function.Function;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;

import com.in28minutes.springboot.myfirstwebapp.login.*;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration {
	//LDAP or Database
	//In Memory 
	
	//InMemoryUserDetailsManager
	//InMemoryUserDetailsManager(UserDetails... users)
    @Autowired
    private DataSource dataSource;
	
	@Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
         
        return authProvider;
    }
	 
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
 
	
	//All URLs are protected
	//A login form is shown for unauthorized requests
	//CSRF disable
	//Frames
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
				auth -> auth.anyRequest().authenticated());
		http.formLogin()
			.usernameParameter("email")
			.defaultSuccessUrl("/")
			.permitAll();
		http.csrf().disable();
		http.headers().frameOptions().disable();
		
		return http.build();
	}
	
	
	
	
	
}
