package rsh.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import rsh.conf.WebAuthnProperties;
import rsh.user.UserEntity;
import rsh.user.UserService;

import java.nio.ByteBuffer;
import java.security.Principal;
import java.util.*;

@Controller
@SessionAttributes("challenge")
public class AppController {
    @Autowired
    WebAuthnProperties webAuthnProperties;
    @Autowired
    WebAuthnManager webAuthnManager;

    @Autowired
    UserService userService;

    //@Autowired
    //EmailService emailService;

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

    @GetMapping("/logon")
    public String getLogon(
            Model model) {
        UUID uuid = UUID.randomUUID();
        // Convert UUID to byte array
        byte[] uuidBytes = new byte[16];
        ByteBuffer.wrap(uuidBytes)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits());
        // Encode byte array to Base64 string
        String base64Encoded = Base64.getEncoder().encodeToString(uuidBytes);
        model.addAttribute("challenge", uuid.toString());
        webAuthnProperties.setFrom( this.webAuthnProperties );
        return "logon";
    }

    @GetMapping("/sendEmail")
    public String getSendEmail() {
        return "sendEmail";
    }

    @GetMapping("/ott/sent")
    public String getOttSent() {
        return "ottSent";
    }
    @GetMapping("/ott/fail")
    public String getOttFail() {
        return "ottFail";
    }

    @GetMapping(value = "/login/ott", params = {"token"})
    public String getLoginOtt(@RequestParam("token") String token, Model model, Principal principal, HttpSession httpSession) {
        model.addAttribute("token", token);
        return "loginOtt";
    }

    @GetMapping("/registration")
    public String getAccountPage(
            @ModelAttribute WebAuthnProperties webAuthnProperties,
            Model model,
            Principal principal,
            HttpSession httpSession) {
        model.addAttribute("challenge", UUID.randomUUID().toString()); // is defined as Session Attribute
        model.addAttribute("email", httpSession.getAttribute("email")); // is defined as Session Attribute
        model.addAttribute("username", principal.getName()); // is defined as Session Attribute
        webAuthnProperties.setFrom( this.webAuthnProperties );
        return "registration";
    }

    @PostMapping(value="/registration")
    public String postAccountPage(
            @ModelAttribute WebAuthnProperties webAuthnProperties,
            @Valid @NotNull @ModelAttribute("credentialInfo") String credentialInfoJsonAsString,
            @Valid @NotNull @ModelAttribute("email") String email,
            @Valid @NotNull @ModelAttribute("username") String username,
            @ModelAttribute("errors") final List<FieldError> errors,
            @AuthenticationPrincipal User user,
            @SessionAttribute("challenge") String challenge,
            final BindingResult bindingResult,
            final Model model,
            SessionStatus sessionStatus,
            HttpSession httpSession,
            Principal principal
    )  {
        if (bindingResult.hasErrors()) {
            for(var r:bindingResult.getFieldErrors()) {
                errors.add(r);
            }
            return "registration";
        }
        if(username==null || username.length()==0) {
            errors.add(new FieldError("username","username", "username is mandatory."));
            return "registration";
        }
        if(email==null || email.length()==0) {
            errors.add(new FieldError("email","email", "email is mandatory."));
            return "registration";
        }
        if(!email.equals(httpSession.getAttribute("email"))) {
            System.err.println(String.format("tempered email, given:%s expected:%s",email, httpSession.getAttribute("email")));
            errors.add(new FieldError("email","email", "email is not authenticated."));
            return "registration";
        }
        if(!username.equals(httpSession.getAttribute("username"))) {
            System.err.println(String.format("tempered username, given:%s expected:%s",username, httpSession.getAttribute("username")));
            errors.add(new FieldError("username","username", "username is not authenticated."));
            return "registration";
        }
        model.addAttribute("webAuthnProperties", this.webAuthnProperties);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String,Object> credentialInfo = objectMapper.readValue(credentialInfoJsonAsString, Map.class);
            Map<String,Object> credentials = (Map)credentialInfo.get("credentials");
            String id = (String)credentials.get("id");
            var response = (Map)credentials.get("response");
            String responseJSON = objectMapper.writeValueAsString(credentials);
            String attestationObject = (String)response.get("attestationObject"); // "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFKcSGaegYrsjos0mwLnVEDzFPUwVpQECAyYgASFYIIr-YPE5s0x4Q_5pzNNLU0X8_VeuuftF1LTyOgYSasUcIlggSYkh_pLigcWPDfLLBnea8GN_UTPMaQ17ihbu32KUiOk",
            String authenticatorData = (String)response.get("authenticatorData"); // "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFKcSGaegYrsjos0mwLnVEDzFPUwVpQECAyYgASFYIIr-YPE5s0x4Q_5pzNNLU0X8_VeuuftF1LTyOgYSasUcIlggSYkh_pLigcWPDfLLBnea8GN_UTPMaQ17ihbu32KUiOk",
            String clientDataJSON = (String)response.get("clientDataJSON"); // "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSkh0amFHRnNiR1Z1WjJWOSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
            String publicKey = (String)response.get("publicKey"); // "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiv5g8TmzTHhD_mnM00tTRfz9V665-0XUtPI6BhJqxRxJiSH-kuKBxY8N8ssGd5rwY39RM8xpDXuKFu7fYpSI6Q",
            Integer publicKeyAlgorithm = (Integer)response.get("publicKeyAlgorithm"); //-7,
            List<String> transports = (List<String>)response.get("transports"); // [ "hybrid", "internal" ]
            var userCredentials = credentialInfoJsonAsString;
            UserEntity userEntity = UserEntity.builder()
                    .id(id)
                    .email((String)model.getAttribute("email"))
                    .username((String)model.getAttribute("username"))
                    .credentials(credentialInfoJsonAsString)
                    .response(responseJSON)
                    .authenticatorData(authenticatorData)
                    .publicKeyAlgorithm(publicKeyAlgorithm)
                    .publicKey(publicKey)
                    .attestationObject(attestationObject)
                    .challenge(challenge)
                    .transports(Set.copyOf(transports))
                    .build();
            userService.save(userEntity);
            sessionStatus.setComplete(); // TODO does this really reset the challenge from session context?
            return "redirect:/login/passkey";
        } catch (JsonProcessingException e) {
            System.err.println(e);
            errors.add(new FieldError("errors","errors", e.getMessage()));
            return "registration";
        } catch (Exception e) {
            System.err.println(e);
            errors.add(new FieldError("errors","errors", e.getMessage()));
            return "registration";
        }
    }

    @GetMapping("/login/passkey")
    public String getLoginPage(
            Model model) {
        UUID uuid = UUID.randomUUID();
        // Convert UUID to byte array
        byte[] uuidBytes = new byte[16];
        ByteBuffer.wrap(uuidBytes)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits());
        // Encode byte array to Base64 string
        String base64Encoded = Base64.getEncoder().encodeToString(uuidBytes);
        System.out.println("Base64 Encoded UUID: " + base64Encoded);
        model.addAttribute("challenge", uuid.toString());
        model.addAttribute("email", ""); // is defined as Session Attribute
        webAuthnProperties.setFrom( this.webAuthnProperties );
        return "login";
    }

    @PostMapping("/login/passkey")
    public String login(
            @Valid @NotNull @ModelAttribute("assertion") String assertionJSONString,
            @SessionAttribute("challenge") String challenge,
            @ModelAttribute("errors") final List<FieldError> errors,
            Principal principal,
            SessionStatus sessionStatus,
            HttpSession session
    ) {
        ObjectMapper objectMapper = new ObjectMapper();
        String credentialId = null;
        try {
            Map<String,Object> assertion = null;
            assertion = objectMapper.readValue(assertionJSONString, Map.class);
            Map<String, Object> response = (Map)assertion.get("response");;
            credentialId = (String)assertion.get("id");
        } catch (JsonProcessingException e) {
            System.err.println(e);
            errors.add(new FieldError("errors","errors", e.getMessage()));
            return "login";
        }

        var maybeUserEntity = userService.byId(credentialId);
        if(maybeUserEntity.isEmpty()) {
            var errmsg = String.format("No user for credentials id:%s", credentialId);
            System.err.println(errmsg);
            errors.add(new FieldError("errors","errors", errmsg));
            return "login";
        }
        var userEntity = maybeUserEntity.get();


        RegistrationData registrationData;
        try {
            String registrationResponseJSON = userEntity.getResponse(); /* set registrationResponseJSON received from frontend */
            registrationData = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJSON);
        }
        catch (DataConversionException e) {
            System.err.println(e.getMessage());
            errors.add(new FieldError("errors","errors", "Error accessing registration data."));
            return "login";
        }

        /* set authenticationResponseJSON received from frontend */

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(assertionJSONString);
        } catch (DataConversionException e) {
            System.err.println(e.getMessage());
            errors.add(new FieldError("errors","errors", "Error accessing registration data."));
            return "login";
        }

// Server properties
        Origin origin = new Origin(webAuthnProperties.getOrigin());
        String rpId = webAuthnProperties.getHostname();
        Challenge challengeObj = new DefaultChallenge(challenge);
        challengeObj = new DefaultChallenge(challenge.getBytes());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challengeObj);

// expectations
        List<byte[]> allowCredentials = null;
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        CredentialRecord credentialRecord =
                new CredentialRecordImpl(
                        registrationData.getAttestationObject(),
                        registrationData.getCollectedClientData(),
                        registrationData.getClientExtensions(),
                        registrationData.getTransports());
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        credentialRecord,
                        allowCredentials,
                        userVerificationRequired,
                        userPresenceRequired
                );

        try {
            webAuthnManager.verify(authenticationData, authenticationParameters);
        } catch (VerificationException e) {
            System.err.println(e.getMessage());
            errors.add(new FieldError("errors","errors", "Error accessing registration data."));
            return "login";
        }
// TODO please update the counter of the authenticator record
//        updateCounter(
//                authenticationData.getCredentialId(),
//                authenticationData.getAuthenticatorData().getSignCount()
//        );

        System.out.println(String.format("Sign Count: credentialId:%s; signCount:%d", authenticationData.getCredentialId(), authenticationData.getAuthenticatorData().getSignCount()));

        var auth = new MyAuthenticationToken(userEntity.getUsername(),
                                             new MyAuthenticationToken.Details(userEntity.getEmail(), userEntity.getId()),
                                             AuthorityUtils.createAuthorityList("USER_ROLE"));
        var securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(auth);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        // also possible:
        //var newSecurityContext = SecurityContextHolder.createEmptyContext();
        //newSecurityContext.setAuthentication(auth);
        //SecurityContextHolder.setContext(newSecurityContext);
        //session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, newSecurityContext);
        return "redirect:/home";
    }
}