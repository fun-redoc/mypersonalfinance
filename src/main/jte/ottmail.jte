@param String bareUrl
@param String target
@param String name
@param String token

<!DOCTYPE html>
<html lang="en">
<body>
<h1>Registration</h1>
<p/>
    Welcome ${name}.
<p/>
    Go to <pre>${bareUrl}</pre> and use the token <pre>${token}</pre> to start the registration.
<p/>
    alternatively follow the link: <a href="${target}" target="_blank">${target}</a>
</body>
</html>