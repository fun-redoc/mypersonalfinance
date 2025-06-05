package rsh.conf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * ATTENTION: this is only for playing around and inspection of whats going on,
 *            don't use in production
 */
public class MySecurityFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                   throws ServletException, IOException
    {
        System.out.println(String.format("ENTERING HELLO IN MY SECURITY FILTER: %s %s",
                            request.getServletPath(), request.getMethod()));
        filterChain.doFilter(request,response);
        var securityContext = SecurityContextHolder.getContext();
        System.out.println(String.format("LEAVING HELLO IN MY SECURITY FILTER: %s %s %s",
                request.getServletPath(), request.getMethod(), securityContext.getAuthentication().getName()));
        if(securityContext.getAuthentication().isAuthenticated() && securityContext.getAuthentication().getPrincipal() != null) {
            var principal = securityContext.getAuthentication().getPrincipal();
            var psincipal2 = request.getUserPrincipal();
            System.out.println(String.format("LEAVING HELLO IN MY SECURITY FILTER: prinicpal set to %s %s", principal, psincipal2));

        }

    }
}
