package rsh.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.util.ArrayList;

public class ControllerBase {
    @Autowired
    UserRepository userRepository;

    protected UserEntity getUserEntity() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        var userName = ((String) auth.getPrincipal()); // ugly upcast, so is the framework
        var maybeRegisteredUser = userRepository.findUserByUsername(userName);
        if (maybeRegisteredUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found.");
        } else {
            return maybeRegisteredUser.get();
        }
    }
    protected static void bindingResultToError(BindingResult bindingResult, ErrorsViewModel errorsViewModel) {
        for(var bindingError: bindingResult.getFieldErrors()) {
            if(!errorsViewModel.getFieldMessages().containsKey(bindingError.getField())) {
                errorsViewModel.getFieldMessages().put(bindingError.getField(),new ArrayList<>());
            }
            var fieldMessages = errorsViewModel.getFieldMessages().get(bindingError.getField());
            fieldMessages.add(bindingError.getDefaultMessage());
        }
    }
}