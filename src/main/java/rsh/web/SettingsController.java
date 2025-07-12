package rsh.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserBaseDto;
import rsh.user.UserRepository;
import rsh.user.UserService;

import java.security.Principal;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

@Controller
@SessionAttributes("challenge")
@RequestMapping("/settings")
public class SettingsController {
    @Autowired
    UserRepository userRepository;
    @Autowired
    UserService userService;
    @Autowired
    OwnerRepository ownerRepository;

    @Autowired
    MessageSource messageSource;

    @ModelAttribute("username")
    public String username() {
        return userService.getUserEntity().getUsername();
    }

    @ModelAttribute("allUsers")
    public List<UserBaseDto> allUsers() {
        var allUsers = userRepository.findAllUsersWithBaseDto();
        return allUsers;
    }

    @ModelAttribute("allOwnersForUser")
    public List<OwnerEntity> allOwnersForUser() {
        var user = userService.getUserEntity();
        var owners = ownerRepository.findOwnerByUser(user);
        return owners;
    }

    @ModelAttribute("allOwnersUserIsAdmin")
    public List<OwnerEntity> allOwnersUserIsAdmin() {
        var user = userService.getUserEntity();
        var owners = ownerRepository.findOwnersByAdminFetchingUsers(user);
        return owners;
    }

    @GetMapping
    public String getSettings(@ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel) {
        return "settings";
    }

}