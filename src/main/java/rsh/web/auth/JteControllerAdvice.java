package rsh.web.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.ui.Model;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.ResponseStatus;
import rsh.conf.JteLocalizer;

import java.util.ArrayList;

@ControllerAdvice
public class JteControllerAdvice {
    public enum MenuItem{HOME, WEALTH, DEPOSITS, POSTS, ACOOUNTS, SETTINGS, LOGOUT};
    @ModelAttribute
    public void currentMenu(Model model, MenuItem menuItem) { model.addAttribute("currentMenu", menuItem);}

    @ModelAttribute
    public void errors(Model model, ArrayList<FieldError> errors) {
        model.addAttribute("errors", errors);
    }

    @ModelAttribute
    public void csrf(Model model, CsrfToken csrf) {
        model.addAttribute("csrf", csrf);
    }

    @ModelAttribute
    public void localizer(Model model, JteLocalizer localizer) {model.addAttribute("localizer", localizer);}

//    @ResponseStatus(HttpStatus.CONFLICT)  // 409
//    @ExceptionHandler(DataIntegrityViolationException.class)
//    public void handleConflict(HttpServletRequest req, Exception e) {
//        // Nothing to do
//        System.err.println(e);
//    }
}
