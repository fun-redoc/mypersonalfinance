@import org.springframework.security.web.csrf.CsrfToken
@import org.springframework.validation.FieldError
@import java.util.List
@import rsh.conf.JteLocalizer
@param JteLocalizer localizer
@param CsrfToken csrf
@param String challenge
@param String email
@param List<FieldError> errors

@template.layout(
    localizer = localizer,
    page = localizer.localize("login.passkey.page"),
    additional_head = @`
        <script src="/login.js"></script>
    `,
    content = @`
        @if(errors==null||errors.size()==0)
            <!-- even if there is no errors from controlleres the div is needed for javascript errors -->
            <div hidden id="errors" >
                <label for="errorList">${localizer.localize("errors.title")}</label>
                <ul id="errorList"> </ul>
            </div>
        @else
            <div id="errors" >
                <label for="errorList">${localizer.localize("errors.title")}</label>
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
            <label for="email">${localizer.localize("login.passkey.user.email")}</label>
            <input id="email" name="email" type="email" placeholder='${localizer.localize("login.passkey.placeholder.email")}' />
            @if(errors!=null && errors.size()>0)
                @for(FieldError err:errors.stream().filter(e->e.getField().equals("email")).toList())
                    <label for="email">${err.getDefaultMessage()}</label>
                @endfor
            @endif
            <!-- type is button to be able to control the behaviour on submitting -->
            <button id="submitPasskey" role="button" type="button">${localizer.localize("login.passkey.logon")}</button>
        </form>
    `,
    additional_script = @`
        <script>
            document.addEventListener("DOMContentLoaded",  () => {
                console.log("document loaded");
                submitPasskey.addEventListener("click", evt=>{
                    if(!email.value) {
                        addError('${localizer.localize("login.passkey.error.empty.email")}');
                        return;
                    }
                    generateAssertionForLogin("${challenge}")
                .then(assertion => {
                    //console.log("assertion:", assertion);
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
                // put additional fields for webauthn
                evt.formData.set('assertion', loginForm.dataset.assertion);
            });
        });
        </script>
    `
)

<%--
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
    --%>