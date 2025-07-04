@import rsh.conf.JteLocalizer
@import rsh.domain.account.AccountRepository
@import rsh.web.AppController
@import rsh.web.JteControllerAdvice
@import java.util.List
@param JteLocalizer localizer
@param String name
@param List<AccountRepository.AccountsBaseData> accounts

@template.layout(localizer =localizer,
currentMenu = JteControllerAdvice.MenuItem.ACOOUNTS,
page = localizer.localize("accounts.page"),
content = @`
    <p><strong>${localizer.localize("accounts.welcome")}</strong></p>

    @for(var account:accounts)
        <p>${account.getName()}</p>
    @endfor

    <!-- List of Accounts -->
    @if(accounts.isEmpty())
        <p>${localizer.localize("accounts.empty")}</p>
    @else
        <section>
            <h2>${localizer.localize("accounts.my_accounts")}</h2>
            <table>
                <thead>
                <tr>
                    <th>${localizer.localize("accounts.account.id")}</th>
                    <th>${localizer.localize("accounts.account.type")}</th>
                    <th>${localizer.localize("accounts.account.name")}</th>
                    <th>${localizer.localize("accounts.account.balance")}</th>
<%--                    <th th:unless="${"hide_actions==true}" >${localizer.localize("accounts.account.actions")}</th> --%>
                </tr>
                </thead>
                <tbody>
                    @for(var account:accounts)
                        <tr>
                            <td>${account.getId()}</td>
                            <td>${account.getAccountType()}</td>
                            <td>${account.getName()}</td>
                            <td>${account.getKred().subtract(account.getDeb())}</td>
                    <%--        <td th:unless="${hide_actions==true}">
                                <a th:href="@{/accounts/edit/{id}(id=${account.id})}" role="button" th:text="#{button.text.edit}">Edit</a>
                                <a th:href="@{/accounts/delete/{id}(id=${account.id})}" role="button" class="secondary" th:text="#{button.text.delete}">Delete</a>
                            </td> --%>
                        </tr>
                    @endfor
                </tbody>
            </table>
        </section>
    @endif

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