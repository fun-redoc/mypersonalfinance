package rsh.conf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import rsh.api.TestEnvRestController;
import rsh.user.UserEntity;
import rsh.user.UserRepository;
import rsh.web.MyAuthenticationToken;

import java.io.IOException;

/**
 * ATTENTION: this is only for playing around and inspection of whats going on,
 *            don't use in production
 */
public class DevelLogonSecurityFilter extends OncePerRequestFilter {
    UserRepository userRepository;
    public DevelLogonSecurityFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                   throws ServletException, IOException
    {
        HttpSession session = request.getSession(false); // true: if no session exists create one
        if(session == null) {
            session = request.getSession(true);
        }

        var securityContext = SecurityContextHolder.getContext();
        if(session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) == null) {
            var users = userRepository.findAll();
            UserEntity userEntity = users.stream().findFirst().orElseThrow(() -> new ServletException("no user found, create on user first."));
            var userDetails = new UserDetailsImpl(userEntity);
            var auth = new MyAuthenticationToken(userEntity.getUsername(),
                    //new MyAuthenticationToken.Details(userEntity.getEmail(), userEntity.getId()),
                    userDetails,
                    AuthorityUtils.createAuthorityList(userDetails.getAuthorities().stream().map(a->a.getAuthority()).toList()));
            //AuthorityUtils.createAuthorityList("USER_ROLE"));
            securityContext.setAuthentication(auth);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        }
        filterChain.doFilter(request,response);  // go on with the filterchain
    }
}
