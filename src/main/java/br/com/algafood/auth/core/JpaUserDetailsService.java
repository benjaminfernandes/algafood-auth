package br.com.algafood.auth.core;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.com.algafood.auth.domain.Usuario;
import br.com.algafood.auth.domain.UsuarioRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Transactional(readOnly = true)//Para manter o entityManager aberto, também poderia ser resolvido fazendo um join fetch
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = this.usuarioRepository.findByEmail(username)
					.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado!"));
		
		return new AuthUser(usuario, getAuthorities(usuario));
	}

	private Collection<GrantedAuthority> getAuthorities(Usuario usuario){
		return usuario.getGrupos().stream()
			.flatMap(grupo -> grupo.getPermissoes().stream())//flatMap achata os dados para ficar linear, utilizado em listas de listas... neste caso não queremos a lista de grupos, mas sim lista de permissoes
			.map(permissao -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
			.collect(Collectors.toSet());
	}
	
}
