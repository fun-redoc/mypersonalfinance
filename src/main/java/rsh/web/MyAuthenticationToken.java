package rsh.web;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public final class MyAuthenticationToken extends AbstractAuthenticationToken {
    public  record Details(String email, String id){};
    private String username;
    private Details details;
    public MyAuthenticationToken(String username,
                                 Details details,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.details = details;
        this.username = username;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

    @Override
    public Object getDetails() {
        return this.details;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }
    @Override
    public void setAuthenticated(boolean authenticated) {
        throw new IllegalArgumentException("trying to change immutable authentication object.");
    }
}
