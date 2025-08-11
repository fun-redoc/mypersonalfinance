<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head th:insert="~{fragments.html::head(page=#{new_wealth.page})}"></head>
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
    <link rel="stylesheet" href="/new_wealth.css">
    <script src="/yFinApiService.js"></script>
    <script src="/new_wealth.js"></script>
</head>
<body>

<header th:replace="~{fragments.html::header(page=#{new_wealth.page})}"></header>

<main class="container">

    <div th:if="${param.fail}">
        <div class="error-message">
        <p th:text="#{error.message.generics}"></p>
        </div>
    </div>

    <form id="formNewInvestment"
          method="post"
          th:action="@{/wealth/edit}"
          th:object="${wealthViewModel}">

        <ul id="errors">
          <li id="errNoApiKey" hidden th:text="#{new_wealth.error.no.api}"></li>
          <!-- <li th:each="err : ${#fields.allErrors()}" th:text="${err}" /> -->
        </ul>

        <input hidden th:field="*{id}"></input>

        <label aria-busy="false" id="searchBoxLabel" for="search" th:text="#{new_wealth.search}">Search:</label>
        <input
                type="search"
                id="searchBox"
                name="symbol"
                th:attr="data-username=${username}"
                th:placeholder="#{new_wealth.search}"
                th:aria-label="#{new_wealth.search}"
                th:value="*{symbol}"
        />
        <ul id="resultsList">
          <template id="searchResultTemplate">
            <li></li>
          </template>
          <li th:each="wealth : ${allWealth}"
                    th:attr="data-wealthlist=true,data-id=${wealth.id},data-symbol=${wealth.symbol},data-name=${wealth.name}"
                    th:text="${wealth.symbol}+':'+${wealth.name}"></li>
        </ul>
        <p th:if="${#fields.hasErrors('symbol')}" th:errorclass="error" th:errors="*{symbol}"></p>

        <label for="name" th:text="#{new_wealth.name}">Name:</label>
        <input type="text" id="name" th:field="*{name}"/>
        <p th:if="${#fields.hasErrors('name')}" th:errorclass="error" th:errors="*{name}"></p>

        <label for="isin" th:text="#{new_wealth.isin}">isin:</label>
        <input type="text" id="isin" th:field="*{isin}"/>
        <p th:if="${#fields.hasErrors('isin')}" th:errorclass="error" th:errors="*{isin}"></p>

        <label for="wkn" th:text="#{new_wealth.wkn}">wkn:</label>
        <input type="text" th:field="*{wkn}"/>
        <p th:if="${#fields.hasErrors('wkn')}" th:errorclass="error" th:errors="*{wkn}"></p>

  <!-- purchases -->
  <div >
      <legend th:text="#{new_wealth.purchases.title}"></legend>
      <table>
          <thead>
          <tr>
              <th th:text="#{new_wealth.purchase.col.nr}">Nr.</th>
              <th th:text="#{new_wealth.purchase.col.id}">Id</th>
              <th th:text="#{new_wealth.purchase.col.date}">purchase Date</th>
              <th th:text="#{new_wealth.purchase.col.units}">Units</th>
              <th th:text="#{new_wealth.purchase.col.price.per.unit}">Price p.u.</th>
              <th th:text="#{new_wealth.purchase.col.fee}">Fee</th>
              <th th:text="#{new_wealth.purchase.col.bank}">Bank</th>
              <th th:text="#{new_wealth.purchase.col.action}">Action</th>
          </tr>
          </thead>
          <tbody>
            <tr id="purchaseInputRow" hidden="true" >
              <td></td>
              <td><input type="hidden" th:field="*{newPurchase.id}"></input> </td>
              <td><input type="date"   th:field="*{newPurchase.purchaseDate}"></input> </td>
              <td><input type="number" th:field="*{newPurchase.units}"></input> </td>
              <td><input type="number" th:field="*{newPurchase.pricePerUnit}"></input> </td>
              <td><input type="number" th:field="*{newPurchase.fee}"></input> </td>
              <td><input type="text"   th:field="*{newPurchase.bank}"></input> </td>
              <td><button id="btnAddPurchase" name="add_purchase" type="submit"
                          th:text="#{new_wealth.purchase.add}"></button> </td>
            </tr>
          <tr th:each="p,s:*{purchases}">
              <td th:text="${s.count}"></td>
              <td>
                <span th:text="${p.id}"/>
                <input type="hidden" th:field="*{purchases[__${s.index}__].id}"></input>
                <input type="hidden" th:field="*{purchases[__${s.index}__].purchaseDate}"></input>
                <input type="hidden" th:field="*{purchases[__${s.index}__].units}"></input>
                <input type="hidden" th:field="*{purchases[__${s.index}__].pricePerUnit}"></input>
                <input type="hidden" th:field="*{purchases[__${s.index}__].fee}"></input>
                <input type="hidden" th:field="*{purchases[__${s.index}__].bank}"></input>
              </td>
              <td th:text="${p.purchaseDate}">Date</td>
              <td th:text="${p.units}">Units</td>
              <td th:text="${p.pricePerUnit}">Price</td>
              <td th:text="${p.fee}">Price</td>
              <td th:text="${p.bank}">Bank</td>
              <td>
                  <button id="btnRemovePurchase" name="remove_purchase" type="submit"
                          class="removePurchase"
                          th:attr="data-id=${p.id}"
                          th:text="#{new_wealth.purchase.remove}"></button>
              </td>
          </tr>
          </tbody>
      </table>
  </div>

        <div role="group">
            <button role="button"
                    class="secondary reset_button"
                    type="reset"
                    th:text="#{button.text.reset}">
                Reset
            </button>
            <button role="button"
                    class="secondary cancel_button"
                    type="reset"
                    th:text="#{button.text.cancel}">
                Cancel
            </button>
            <button autofocus type="submit"
                    role="button"
                    class="primary"
                    th:text="#{button.text.submit}">
                Submit
        </button>
    </div>
    </form>


</main>
<footer th:replace="~{fragments.html::footer}"></footer>

</body>
</html>