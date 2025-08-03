@import gg.jte.Content
@import rsh.conf.JteLocalizer
@import rsh.web.auth.JteControllerAdvice
@param JteLocalizer localizer
@param JteControllerAdvice.MenuItem currentMenu = null
@param Content page
@param Content additional_head = null
@param Content content
@param Content additional_script = null

<!DOCTYPE html>

!{ var menuClassDeposits = "secondary"; }
!{ var menuClassHome = "secondary"; }
!{ var menuClassAccounts = "secondary"; }
!{ var menuClassLogout = "secondary"; }
!{ var menuClassPosts = "secondary"; }
!{ var menuClassSettings = "secondary"; }
!{ var menuClassWealth = "secondary"; }
@if(currentMenu!= null)
    @if(currentMenu == JteControllerAdvice.MenuItem.DEPOSITS)
        !{menuClassDeposits = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.HOME)
        !{menuClassHome = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.ACOOUNTS)
        !{menuClassAccounts = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.LOGOUT)
        !{menuClassLogout = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.POSTS)
        !{menuClassPosts = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.SETTINGS)
        !{menuClassSettings = "primary";}
    @endif
    @if(currentMenu == JteControllerAdvice.MenuItem.WEALTH)
        !{menuClassWealth = "primary";}
    @endif
@endif

<html lang="EN-en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <link rel="stylesheet" href="/pico.min.css">
    <link rel="stylesheet" href="/style.css">
    <script src="/modal.js" defer></script>
    @if(additional_head != null)
        ${additional_head}
    @endif
    <title>${localizer.localize("fragments.title.my_finance")} -  ${page}</title>
</head>

<body>

    <header>
        <nav>
            <ul>
                <li><strong><a href="#"> ${localizer.localize("fragments.title.my_finance")} - ${page}</a></strong></li>
            </ul>
            <ul>
                <li> <a href="/"         class="${menuClassHome}"> ${localizer.localize("fragments.navigation.home")}</a> </li>
                <li> <a href="/wealth"   class="${menuClassWealth}"> ${localizer.localize("fragments.navigation.wealth")}</a> </li>
                <li> <a href="/deposits" class="${menuClassDeposits}"> ${localizer.localize("fragments.navigation.deposits")}</a> </li>
                <li> <a href="/posts"    class="${menuClassPosts}"> ${localizer.localize("fragments.navigation.posts")}</a> </li>
                <li> <a href="/accounts" class="${menuClassAccounts}"> ${localizer.localize("fragments.navigation.accounts")}</a> </li>
                <li> <a href="/settings" class="${menuClassSettings}"> ${localizer.localize("fragments.navigation.settings")}</a> </li>
                <li> <a href="/logout"   class="${menuClassLogout}"> ${localizer.localize("fragments.navigation.logout")}</a> </li>
            </ul>
        </nav>
    </header>

    <main class="container">
        <section>
            ${content}
        </section>
    </main>

    <footer>${localizer.localize("fragments.footer.copyright")}</footer>

    @if(additional_script != null)
        ${additional_script}
    @endif
</body>

</html>