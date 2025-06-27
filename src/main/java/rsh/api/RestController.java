package rsh.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

@org.springframework.web.bind.annotation.RestController
public class RestController {
    @Autowired
    UserRepository userRepository;

    @GetMapping("/api/self/details")
    public UserEntity getAccounts() {
       var me = getUserEntity();
       return me;
    }
    protected UserEntity getUserEntity() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        var userDetails = auth.getPrincipal();
        // TODO see MyAuthenticationToken class, getPricipal return String, maybe it shoould return as UserDetail object.
        //      like this:
        //      var userName = ((UserDetails) userDetails).getUsername(); // ugly upcast, so is the framework
        var userName = ((String) userDetails); // ugly upcast, so is the framework
        var maybeRegisteredUser = userRepository.findUserByUsername(userName);
        if (maybeRegisteredUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found.");
        } else {
            return maybeRegisteredUser.get();
        }
    }
}
