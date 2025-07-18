package rsh.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    @Autowired
    UserRepository userRepository;

    //@Autowired
    //public UserService(UserRepository userRepository) {
    //    this.userRepository = userRepository;
    //}
    //public Optional<UserEntity> byUsername(String username) {
    //    return userRepository.findUserByUsername(username);
    //}
    //public Optional<UserEntity> byId(String id) {
    //    return userRepository.findById(id);
    //}

    //public UserEntity save(UserEntity user) {
    //    return userRepository.save(user);
    //}

    // TODO discard UserService class in favour of BaseController
    //public UserEntity getUserEntity() {
    //    var auth = SecurityContextHolder.getContext().getAuthentication();
    //    var userName = ((String) auth.getPrincipal()); // ugly upcast, so is the framework
    //    var maybeRegisteredUser = userRepository.findUserByUsername(userName);
    //    if (maybeRegisteredUser.isEmpty()) {
    //        throw new UsernameNotFoundException("User not found.");
    //    } else {
    //        return maybeRegisteredUser.get();
    //    }
    //}
}