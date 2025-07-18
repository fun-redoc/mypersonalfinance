package rsh.web;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import rsh.user.UserBaseDto;

import java.util.Collection;

public final class MyAuthenticationToken extends AbstractAuthenticationToken {
    //public  record Details(String email, String id){};
    private final UserBaseDto user;
    //private Details details;
    private UserDetails details;
    public MyAuthenticationToken(UserBaseDto user,
                                 UserDetails details,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.details = details;
        this.user = user;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public String getName() {
        return user.getUsername();
    }

    @Override
    public Object getPrincipal() {
        return this.user;
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
