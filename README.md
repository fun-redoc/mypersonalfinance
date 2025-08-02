## Pesonal Finance Tool (MyFinx)

I want to manage my saving accounts, interest rates, stock etc. in one tool.
It should be accessible from a clud e.g. render.com.
Confidential Data like IBAN, Asset names, Asset ISIN/WKN, should be end-to-end encrypted.
Registration via one time token.
Login via passkey.
No passwords should be stored.

### IN PROGRESS
+ BUG: Add first Deposit to an empty Deposits list
+ savings/deposits edit

### DONE
+ register for passkey login with e-mail verification
+ create accounts
+ user who can manage the account
+ manage groups
+ edit account
+ delete account
+ savings/deposits list
+ savings/deposits add
+ savings/deposits delete
  
### TODO
+ give post a name
+ posts list
+ posts add
+ posts delete
+ posts edit
+ adjust post selection in deposits having post name
+ make tag reusable within an owner group and provide autocompletion of tags whitin deposit new/edit dialog
+ make a productive version
+ adjust comments, create some tech documentation
+ TEST: try with mass data and mass requests
+ wealth/stock search yfin api show result
+ wealth/stock list assets
+ wealth/stock add transaction
+ wealth/stock upload transactions from csv
+ wealth/stock manage watchlist add
+ wealth/stock manage watchlist remove
+ wealth/stock manage watchlist stock details view
+ wealth/stock remove transaction (questionable)
+ BUG: accounts add, after error message (e.g no account type) group selection disappears
+ BUG: modal dialogs allways scroll to botton after opening initially, better stay scrolled to the top
+ make ready for cloud (e.g. render.com)
+ record video
+ make description and documentation



### TRYOUT
+ merge deposit entity and interest entity in one entity or one to one
+ make entities cachable
+ Make associations TRANSACTION cachable
+ one time toke and user management, try only to store email adress end-to-end-encrypted.
