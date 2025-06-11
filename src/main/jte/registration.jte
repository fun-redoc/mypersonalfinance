@import org.springframework.security.web.csrf.CsrfToken
@import org.springframework.validation.FieldError
@import rsh.conf.WebAuthnProperties
@import java.util.List
@import rsh.conf.JteLocalizer
@param JteLocalizer localizer
@param CsrfToken csrf
@param WebAuthnProperties  webAuthnProperties
@param String challenge
@param String email
@param String username
@param List<FieldError> errors

@template.layout(
    localizer = localizer,
    page = localizer.localize("registration.page"),
    additional_head = @`
        <script src="/registration.js"></script>
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

        <form id="registerForm" action="/registration" method="post">
            @if(csrf != null)
                <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
            @endif
            <label for="passkeyName">${localizer.localize("registration.passkey.name")}</label>
            <input id="passkeyName" type="text" placeholder='${localizer.localize("registration.placeholder.passkey.name")}'/>
            <label for="username">${localizer.localize("registration.user.name")}</label>
            <input id="username" name="username" type="text" placeholder='${localizer.localize("registration.placeholder.user.name")}' value="${username}" />
            @if(errors!=null && errors.size()>0)
                @for(FieldError err:errors.stream().filter(e->e.getField().equals("username")).toList())
                    <label for="username">${err.getDefaultMessage()}</label>
                @endfor
            @endif
            <label for="email">${localizer.localize("registration.user.email")}</label>
            <input id="email" name="email" type="email" placeholder='${localizer.localize("registration.placeholder.email")}' value="${email}"/>
            @if(errors!=null && errors.size()>0)
                @for(FieldError err:errors.stream().filter(e->e.getField().equals("email")).toList())
                    <label for="email">${err.getDefaultMessage()}</label>
                @endfor
            @endif
            <!-- type is button to be able to control the behaviour on submitting -->
            <button id="submitPasskey" role="button" type="button">${localizer.localize("registration.submit.button")}</button>
        </form>
    `,
    additional_script = @`
        <script>
            document.addEventListener("DOMContentLoaded",  () => {
                console.log("document loaded");
                //clearAndHideErrors();
                submitPasskey.addEventListener("click", evt=>{
                    console.log("submit");
                    if(!passkeyName.value) {
                        addError('${localizer.localize("registration.error.please.provide.a.name.for.your.passkey")}');
                    } else {
                        clearAndHideErrors();
                    }
                    try {
                        registerPasskey("${challenge}", passkeyName.value, "${webAuthnProperties.getDisplay()}", username.value, email.value)
                      .then(function (newCredentialInfo) {
                        // Send new credential info to server for verification and registration.
                        registerForm.dataset['newCredentialInfo'] = JSON.stringify({credentials:newCredentialInfo, name:passkeyName.value});
                        registerForm.submit();
                      }).catch(function (err) {
                        // No acceptable authenticator or user refused consent. Handle appropriately.
                        addError(err);
                      });
                } catch(err) {
                    addError(err);
                }
            });
            //addPasskey.onclick = (evt) => {
            registerForm.addEventListener("formdata", evt => {
                // put additional fields for webauthn
                evt.formData.set('credentialInfo', registerForm.dataset.newCredentialInfo );
            });
        });
        </script>
    `
)

<%--
<!DOCTYPE html>
<html>
<head>
    <script src="/registration.js"></script>
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

<form id="registerForm" action="/registration" method="post">
    @if(csrf != null)
        <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
    @endif
    <label for="passkeyName">Passkey Name</label>
    <input id="passkeyName" type="text" placeholder="name your passkey..."/>
    <label for="username">User Name</label>
    <input id="username" name="username" type="text" placeholder="provide your name..." value="${username}" />
    @if(errors!=null && errors.size()>0)
        @for(FieldError err:errors.stream().filter(e->e.getField().equals("username")).toList())
            <label for="username">${err.getDefaultMessage()}</label>
        @endfor
    @endif
    <label for="email">email</label>
    <input id="email" name="email" type="email" placeholder="provide your email..." value="${email}"/>
    @if(errors!=null && errors.size()>0)
        @for(FieldError err:errors.stream().filter(e->e.getField().equals("email")).toList())
            <label for="email">${err.getDefaultMessage()}</label>
        @endfor
    @endif
    <button id="submitPasskey" role="button" type="button"><!-- type is button to be able to control the behaviour on submitting -->Add Passkey</button>
</form>

<script>
    document.addEventListener("DOMContentLoaded",  () => {
        console.log("document loaded");
        //clearAndHideErrors();
        submitPasskey.addEventListener("click", evt=>{
            console.log("submit");
            if(!passkeyName.value) {
                addError("please provide a name for your passkey.");
            } else {
                clearAndHideErrors();
            }
            try {
                registerPasskey("${challenge}", passkeyName.value, "${webAuthnProperties.getDisplay()}", username.value, email.value)
                  .then(function (newCredentialInfo) {
                    // Send new credential info to server for verification and registration.
                    console.log(newCredentialInfo);
                    registerForm.dataset['newCredentialInfo'] = JSON.stringify({credentials:newCredentialInfo, name:passkeyName.value});
                    registerForm.submit();
                  }).catch(function (err) {
                    // No acceptable authenticator or user refused consent. Handle appropriately.
                    addError(err);
                  });
            } catch(err) {
                addError(err);
            }
        });
        //addPasskey.onclick = (evt) => {
        registerForm.addEventListener("formdata", evt => {
            console.log("form data");
            // put additional fields for webauthn
            evt.formData.set('credentialInfo', registerForm.dataset.newCredentialInfo );
        });
    });
</script>
</body>
</html>
    --%>