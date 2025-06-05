@import org.springframework.security.web.csrf.CsrfToken
@import org.springframework.validation.FieldError
@import java.util.List
@param CsrfToken csrf
@param String recipient
@param String name
@param List<FieldError> errors

<!DOCTYPE html>
<html lang="en">
<body>
<h1>Request Registration mail</h1>
<form id="sendEmailForm" action="/ott/generate" method="post">
    @if(csrf != null)
        <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
    @endif
    <label for="userName">User Name</label>
    <input id="userName" name="username" type="text" placeholder="provide your name..." />
    @if(errors!=null && errors.size()>0)
        @for(FieldError err:errors.stream().filter(e->e.getField().equals("username")).toList())
            <label for="userName">${err.getDefaultMessage()}</label>
        @endfor
    @endif
    <label for="email">email</label>
    <input id="email" name="email" type="email" placeholder="provide your email..." />
    @if(errors!=null && errors.size()>0)
        @for(FieldError err:errors.stream().filter(e->e.getField().equals("email")).toList())
            <label for="email">${err.getDefaultMessage()}</label>
        @endfor
    @endif
    <button id="submitPasskey" role="button" type="submit"><!-- type is button to be able to control the behaviour on submitting -->Add Passkey</button>
</form>

</body>
</html>>