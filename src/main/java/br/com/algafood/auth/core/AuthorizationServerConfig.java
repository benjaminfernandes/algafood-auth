package br.com.algafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	//@Autowired
	//private PasswordEncoder encoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties; 
	
	@Autowired
	private DataSource dataSource;
	
	//@Autowired configura????o do para utilizar o redis
	//private RedisConnectionFactory redisConnectionFactory;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients.jdbc(dataSource);//via banco de dados
		
		
		/*
		 * Configura????o inMemory...
		 * 
		 * clients
			.inMemory()
				.withClient("algafood-web")
				.secret(encoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")//informa o fluxo utilizado, ex password, client-credentials
				.scopes("WRITE", "READ")
				.accessTokenValiditySeconds(6 * 60 * 60) // horas
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) //60 dias
			.and()
				.withClient("app-mobile")
				.secret(encoder.encode("mobile123"))
				.authorizedGrantTypes("password")
				.scopes("WRITE", "READ")
				.accessTokenValiditySeconds(600)
			.and()
				.withClient("faturamento")
				.secret(encoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("WRITE", "READ")
			.and()
				.withClient("foodanalytics")
				.secret(encoder.encode("food123"))//Authorization code n??o ?? obrigat??rio o password - o ideal ?? ter o client_secret e dar a op????o para o cliente autenticar com client_secret ou pkce
				.authorizedGrantTypes("authorization_code")
				.scopes("WRITE", "READ")
				.redirectUris("http://aplicacao-cliente")
			.and()
				.withClient("checktoken")//libera a uri de checagem de token
					.secret(encoder.encode("check123"));*/
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()")//Expressoes de seguran??a do spring security - Indica que para acessar este endpoint deve estar authenticado /oauth/check_token
		.tokenKeyAccess("permitAll()")//permite utilizar o endpoint /oauth/token_key para capturar a chave p??blica da assinatura assim??trica do token
		.allowFormAuthenticationForClients();//indica que pode ser passado o client_id como uma chave no corpo da requisi????o - Authentication code flow PKCE
		//security.checkTokenAccess("permitAll()");		
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(this.authenticationManager) //somente o fluxo password utiliza o authentication manager para validar o usuario e senha do usu??rio final
			.userDetailsService(userDetailsService)
			.tokenGranter(tokenGranter(endpoints))
			.reuseRefreshTokens(false)//invalida a reutiliza????o do refresh token.
			.accessTokenConverter(jwtAccessTokenConverter()) //ele tamb??m implementa o TokenEnhancer
			.tokenEnhancer(enhancerChain)
			.approvalStore(approvalStore(endpoints.getTokenStore()));//aula 23.13 deve ser sempre ap??s o accessTokenConverter
			//.tokenStore(redisTokenStore());

	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	} 
	
	/*private TokenStore redisTokenStore() {
		return new RedisTokenStore(this.redisConnectionFactory);
	}*/

	//Aulas 23.09 a 23.11
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
		//jwtAccessTokenConverter.setSigningKey("8a9sf5asdf6a4sd6f48sd45fa4sd65f48asd4f65ad4sf8d5d5d5d8sa65");//utiliza o algoritmo hmacsha26 assinatura simetrica
		
		var jksResource = new ClassPathResource(this.jwtKeyStoreProperties.getPath());
		var keyStorePass = this.jwtKeyStoreProperties.getPassword(); //senha para abrir o arquivo jks
		var keyPairAlias = this.jwtKeyStoreProperties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
	
}
