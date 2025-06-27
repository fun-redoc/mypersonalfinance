package rsh.conf;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import rsh.user.UserEntity;

import javax.naming.AuthenticationNotSupportedException;
import java.util.Collection;
import java.util.List;

public class UserDetailsImpl implements UserDetails {
    public static enum ROLES{USER_ROLE, ADMIN_ROLE};

        final UserEntity user;
        public UserDetailsImpl(UserEntity user) {
            this.user = user;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            // TODO pick ROLE from DB
            if(user.getUsername().equals("h2")) {
                return List.of(new SimpleGrantedAuthority(ROLES.USER_ROLE.name()),
                               new SimpleGrantedAuthority(ROLES.ADMIN_ROLE.name()));
            }
            else {
                return List.of(new SimpleGrantedAuthority(ROLES.USER_ROLE.name()));
            }
        }

        @Override
        public String getPassword() {
            throw new AuthenticationCredentialsNotFoundException("Password Authentication not Supported");
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            //return UserDetails.super.isAccountNonExpired();
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            //return UserDetails.super.isAccountNonLocked();
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            //return UserDetails.super.isCredentialsNonExpired();
            return true;
        }

        @Override
        public boolean isEnabled() {
            //return UserDetails.super.isEnabled();
            return true;
        }
}
