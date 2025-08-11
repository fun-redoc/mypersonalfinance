@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.account.deposit.DepositDto
@import rsh.domain.account.deposit.DepositListDto
@import rsh.domain.account.deposit.DepositRepository
@import rsh.domain.account.deposit.InterestEntity
@import rsh.web.base.ErrorsViewModel
@import rsh.web.deposit.DepositController
@import rsh.web.auth.JteControllerAdvice
@import rsh.web.base.NullTollerantDateFormatter
@import rsh.web.wealth.WealthController
@import java.text.SimpleDateFormat
@import java.util.Date
@import java.util.List
@param CsrfToken csrf
@param JteLocalizer localizer
@param String username
@param Date today
@param List<WealthController.WealthListViewModel> allWealth
@param WealthController.WealthViewModel wealthViewModel
@param Boolean hide_actions
@param ErrorsViewModel vwerrors

!{NullTollerantDateFormatter formatter = new NullTollerantDateFormatter(new SimpleDateFormat("yyyy-MM-dd"));}

!{var pageContent = @`

    @template.generalErrors(vwerrors = vwerrors, localizer = localizer)

    <div role="group">
        <h2>${localizer.localize("wealth.my_wealth")}</h2>

        <button id="btnNewWealth"
                data-target="modalEditAddDialog"
               >${localizer.localize("wealth.btn.new.wealth")}
        </button>
    </div>


    <!--symotion-f) List of Deposits -->
    @if(!allWealth.isEmpty())
        <table id="wealth-table">
            <thead>
            <tr>
                <th>${localizer.localize("wealth.list.symbol")}</th>
                <th class="hide-on-small hide-on-middle">${localizer.localize("wealth.list.name")}</th>
                <th class="hide-on-small">${localizer.localize("wealth.list.units")}</th>
                <th class="hide-on-small">${localizer.localize("wealth.list.price.per.unit")}</th>
                <th>${localizer.localize("wealth.list.total.value")}</th>
                <th class="hide-on-small hide-on-middle">${localizer.localize("wealth.list.in.portfolio.since")}</th>
                @if(!hide_actions)
                    <th>${localizer.localize("wealth.actions")}</th>
                @endif
            </tr>
            </tr>
            </thead>
            <tbody>
            @for(var wealth:allWealth)
            <tr class="wealth-row" >
                <td>${wealth.symbol()}</td>
                <td class="hide-on-small hide-on-middle">${wealth.name()}</td>
                <td class="hide-on-small"> ${wealth.units()}</td>
                <td class="hide-on-small">${wealth.pricePerUnit()}</td>
                <td>${wealth.totalValue()}</td>
                <td class="hide-on-small hide-on-middle">${formatter.format(wealth.inPortfolioSince())}</td>
                @if(!hide_actions)
                <td>
                    <div role="group">
                        <a href="/wealth/edit/${wealth.id()}" role="button">${localizer.localize("button.text.edit")}</a>
                        <a href="/wealth/delete/${wealth.id()}}" role="button" class="secondary">${localizer.localize("button.text.delete")}</a>
                    </div>
                </td>
                @endif
            </tr>
            @endfor
            </tbody>
        </table>
    @endif
`;}

@template.layout(
localizer =localizer,
currentMenu = JteControllerAdvice.MenuItem.WEALTH,
page = localizer.localize("wealth.page"),
content = pageContent,
additional_head = @`
    <script src="/security.js" ></script>
    <script src="/wealth.js" ></script>
`
)
<%--
<!DOCTYPE html>
<html lang="en"
      xmlns:th="http://www.thymeleaf.org">
<head th:insert="~{fragments.html::head(page=#{wealth.page})}"></head>
<head th:attr="hidden='true'">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <link rel="stylesheet" href="/pico.min.css">
    <link rel="stylesheet" href="/style.css">
    <script src="/modal.js" defer></script>
    <title th:text="#{fragments.title.my_finance}+'-'+${page}">My Finance</title>
</head>
<head>
  <script src="/wealth.js" ></script>
</head>
<body>
<header th:replace="~{fragments.html::header(page=#{wealth.page})}"></header>

<main class="container">

  <div th:if="${param.fail}">
    <div class="error-message">
      <p th:text="#{error.message.generics}"></p>
    </div>
  </div>

  <div role="group">
      <h2 th:text="#{wealth.my_wealth}"></h2>

      <button id="btnNewWealth"
              data-target="modalEditAddDialog"
              th:text="#{wealth.btn.new.wealth}">
      </button>
  </div>


<!-- List of Deposits -->
<section th:unless="${#lists.isEmpty(allWealth)}">
  <table id="wealth-table">
    <thead>
    <tr>
      <th th:text="#{wealth.list.symbol}"></th>
      <th th:text="#{wealth.list.name}" class="hide-on-small hide-on-middle"></th>
      <th th:text="#{wealth.list.units}" class="hide-on-small"></th>
      <th th:text="#{wealth.list.price.per.unit}" class="hide-on-small"></th>
      <th th:text="#{wealth.list.total.value}"></th>
      <th th:text="#{wealth.list.in.portfolio.since}" class="hide-on-small hide-on-middle"></th>
      <th th:unless="${hide_actions==true}"
          th:text="#{wealth.actions}">Actions</th>
    </tr>
    </tr>
    </thead>
    <tbody>
      <tr class="wealth-row"
          th:each="wealth : ${allWealth}">
        <td th:text="${wealth.symbol}"></td>
        <td th:text="${wealth.name}" class="hide-on-small hide-on-middle"></td>
        <td th:text="${wealth.units}" class="hide-on-small"></td>
        <td th:text="${wealth.pricePerUnit}" class="hide-on-small"></td>
        <td th:text="${wealth.totalValue}"></td>
        <td th:text="${wealth.inPortfolioSince}" class="hide-on-small hide-on-middle"></td>
        <td th:unless="${hide_actions==true}">
          <div role="group">
            <a th:href="@{/wealth/edit/{id}(id=${wealth.id})}" role="button" th:text="#{button.text.edit}">Edit</a>
            <a th:href="@{/wealth/delete/{id}(id=${wealth.id})}" role="button" class="secondary" th:text="#{button.text.delete}">Delete</a>
          </div>
        </td>
      </tr>
    </tbody>
  </table>
</section>
</main>
<footer th:replace="~{fragments.html::footer}"></footer>
</body>
</html>
--%>