### WHAT is in

This is an example/template for authentificaiton using passkey.

You can use it as a starter authentication template for your own projects.

The complete flow consists of:
1. request http://localhost:8080, this will redirect to the one time token page http://localhost:8080/sendEmail
2. provide username and email and submit
3. you will receive an email consisting a link to the registration page http://localhost:8080/registration with the one time token to authenticate
4. using the link from the email you can register as user for passkey authentication
5. after registration you can use http://localhost:8080/login/passkey to logon

This template is not ment to be production ready as it is.
It is laking of:
+ appropriate logging
+ bullet proof exceptoion handling
+ styling
+ i8n
+ settings for production
+ tests
+ jte is maybe not the best option

### References

jte: https://jte.gg

jte hints for production: https://github.com/danvega/jte-production

One Time Token: https://docs.spring.io/spring-security/reference/servlet/authentication/onetimetoken.html

Passkeys W3: https://www.w3.org/TR/webauthn-3/#sctn-sample-authentication

Passkeys Spring Security: https://docs.spring.io/spring-security/reference/servlet/authentication/passkeys.html

Passkeys WebAuthn4j: https://webauthn4j.github.io/webauthn4j/en/

WebAuthn4j Examples: https://github.com/webauthn4j/webauthn4j-spring-security-samples

### TODO

+ improve error messages and handling
+ use logger insetead of system.out/err