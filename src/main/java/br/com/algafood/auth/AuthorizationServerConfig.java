package br.com.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(encoder.encode("web123"))
				.authorizedGrantTypes("password")//informa o fluxo utilizado, ex password, client-credentials
				.scopes("write", "read")
				.accessTokenValiditySeconds(600)
			.and()
				.withClient("app-mobile")
				.secret(encoder.encode("mobile123"))
				.authorizedGrantTypes("password")
				.scopes("write", "read");
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()");//Expressoes de segurança do spring security - Indica que para acessar este endpoint deve estar authenticado /oauth/check_token
		//security.checkTokenAccess("permitAll()");		
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(this.authenticationManager); //somente o fluxo password utiliza o authentication manager para validar o usuario e senha do usuário final
	}
	
}