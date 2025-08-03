@import rsh.conf.JteLocalizer
@param JteLocalizer localizer
@param String name
@param boolean enabled = true
@param rsh.web.base.ErrorsViewModel vwerrors


@template.generalErrors(vwerrors = vwerrors)

<article hidden="${!enabled}">
    <header>${localizer.localize("settings.article.header.encryption")}</header>
    <input id="inpKeyPasswd" type="password"
           data-username="${name}"
           placeholder="${localizer.localize("settings.article.encryption.input.password.placeholder")}"/>

    <footer >
        <div role="group">
            <button id="btnCreateKey"
                    role="button"
                    class="primary"
                    type="button">
                    ${localizer.localize("settings.article.encryption.button.create.key")}
            </button>
        </div>
    </footer>
    <script language="JavaScript" >
        // TODO by the rules, no fragments out side fragmens.html and no inline script...fix this
        const btnCreateKey = document.getElementById('btnCreateKey');
        btnCreateKey.addEventListener('click', function() {
            console.log("first listener");
            const inpKeyPasswd = document.getElementById('inpKeyPasswd');
            // TODO should be sessionStorage finally
            //localStorage.setItem("enc.key", inpKeyPasswd.value);
            sessionStorage.setItem("enc.key." + inpKeyPasswd.dataset.username, inpKeyPasswd.value);
        });
    </script>
</article>