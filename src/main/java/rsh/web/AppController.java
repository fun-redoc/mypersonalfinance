package rsh.web;

import jakarta.persistence.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.user.UserService;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Controller
@SessionAttributes("challenge")
public class AppController {
    @Autowired
    AccountRepository accountRepository;
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

    @ModelAttribute("accounts")
    public List<AccountRepository.AccountsBaseData> getModelAttributeAllAccounts() {
        return accountRepository.findBaseWithBalanceByUser(userService.getUserEntity());
    }
    @GetMapping(value = "/accounts")
    public String getAccounts() {
        return "accounts";
    }

}