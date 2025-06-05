@import org.springframework.security.web.csrf.CsrfToken
@param CsrfToken csrf
@param String token

<!DOCTYPE html>
<html lang="en"><head>
    <title>One-Time Token Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
</head>
<body>
    <form action="/login/ott" method="post">
        <h2>Please input the token</h2>
        <p>
            <label for="token" >Token</label>
            <input type="text" id="token" name="token" value="${token}" placeholder="Token" required="true" autofocus="autofocus">
        </p>
        <button class="primary" type="submit">Sign in</button>
        @if(csrf != null)
            <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
        @endif
    </form>
</body></html>