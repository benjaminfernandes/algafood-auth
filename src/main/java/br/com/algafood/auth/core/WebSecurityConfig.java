package br.com.algafood.auth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SuppressWarnings("deprecation")
@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	//@Autowired
	//private UserDetailsService userDetailsService;
	
	/*
	 * Método utilizado para testes rápidos de autenticações
	 * @Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("benjamin")
				.password(passwordEncoder().encode("123456"))
				.roles("ADMIN")
			.and()
			.withUser("joao")
				.password(passwordEncoder().encode("123"))
				.roles("ADMIN");
	}
	*/
	
	
	//Implementação do remember-me Aula 22.27 - Sessão perguntas "Recurso remember-me"
	/*
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.formLogin().loginPage("/login")
			.and()
			.authorizeRequests()
				.antMatchers("/oauth/**").authenticated()
			.and()
			.csrf().disable()
			.cors().and()
			
			//Adicionado logout
			.logout()
				.deleteCookies("JSESSIONID")
			.and()
				
			//Adicionado Remember-me
			.rememberMe()
				.rememberMeParameter("remember-me")
				.tokenValiditySeconds(8000)
				.userDetailsService(userDetailsService)
			.and()
			.userDetailsService(userDetailsService)
				
			.oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter());
	}
	*/
	
	/*
	 * Para testes de usuários em memória
	 * @Bean
	@Override
	protected UserDetailsService userDetailsService() {
		return super.userDetailsService();
	}
	*/
}
