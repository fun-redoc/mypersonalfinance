@import rsh.conf.JteLocalizer
@param JteLocalizer localizer
@param String name

@template.layout(localizer =localizer,
page = localizer.localize("home.page", name),
content = @`
    <p><strong>${localizer.localize("home.welcome", name)}</strong> is logged in.</p>
` )

<%--
<!DOCTYPE html>
<html>
<head>

</head>
<body>
<p><strong>${name}</strong> is logged in.</p>
</body>
</html>
    --%>