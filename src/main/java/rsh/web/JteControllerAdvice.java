package rsh.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.ui.Model;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.ArrayList;

@ControllerAdvice
public class JteControllerAdvice {

    @ModelAttribute
    public void errors(Model model, ArrayList<FieldError> errors) {
        model.addAttribute("errors", errors);
    }

    @ModelAttribute
    public void csrf(Model model, CsrfToken csrf) {
        model.addAttribute("csrf", csrf);
    }
}
