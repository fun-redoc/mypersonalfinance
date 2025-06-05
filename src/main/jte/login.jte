@import org.springframework.security.web.csrf.CsrfToken
@import org.springframework.validation.FieldError
@import java.util.List
@param CsrfToken csrf
@param String challenge
@param String email
@param List<FieldError> errors

<!DOCTYPE html>
<html>
<head>
    <script src="/login.js"></script>
</head>
<body>

@if(errors==null||errors.size()==0)
    <!-- even if there is no errors from controlleres the div is needed for javascript errors -->
    <div hidden id="errors" >
        <label for="errorList">Errors</label>
        <ul id="errorList"> </ul>
    </div>
@else
    <div id="errors" >
        <label for="errorList">Errors</label>
        <ul id="errorList">
            @for(var err:errors)
                <li>${err.getDefaultMessage()}</li>
            @endfor
        </ul>
    </div>
@endif

<form id="loginForm" action="/login/passkey" method="post">
    @if(csrf != null)
        <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
    @endif
    <label for="email">email</label>
    <input id="email" name="email" type="email" placeholder="provide your email..." />
    @if(errors!=null && errors.size()>0)
        @for(FieldError err:errors.stream().filter(e->e.getField().equals("email")).toList())
            <label for="email">${err.getDefaultMessage()}</label>
        @endfor
    @endif
    <button id="submitPasskey" role="button" type="button"><!-- type is button to be able to control the behaviour on submitting -->Logon</button>
</form>

<script>
    document.addEventListener("DOMContentLoaded",  () => {
        console.log("document loaded");
        submitPasskey.addEventListener("click", evt=>{
            console.log("submit");
            if(!email.value) {
                addError("email cannot be empty, please provide a valid email adresse to login.");
                return;
            }
            generateAssertionForLogin("${challenge}")
            .then(assertion => {
                console.log("assertion:", assertion);
                loginForm.dataset['assertion'] = JSON.stringify(assertion); // pass over to the "formdata" event via form data attribute, kind of messy
                loginForm.submit();
            })
            .catch(function(err) {
                console.err("error:", err);
                addError(err);
                return;
            });
        });

        loginForm.addEventListener("formdata", evt => {
            console.log("form data");
            // put additional fields for webauthn
            evt.formData.set('assertion', loginForm.dataset.assertion);
        });
    });
</script>
</body>
</html>