package rsh.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.SessionAttributes;
import rsh.user.UserService;

import java.security.Principal;

@Controller
@SessionAttributes("challenge")
public class HomeController extends ControllerBase {
    @Autowired
    UserService userService;

    @Autowired
    MessageSource messageSource;

    @GetMapping(value =  "/" )
    public String geRoot(
            Principal principal,
            Model model) {
        if(principal != null && principal.getName() != null) {
            return "redirect:/home";
        }
        return "redirect:/logon";
    }

    @GetMapping(value = "/home" )
    public String getHome(
            Principal principal,
            Model model) {
        model.addAttribute("name", principal.getName());
        return "home";
    }

    @ModelAttribute("username")
    public String username() {
        return getUser().getUsername();
    }

}