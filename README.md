## Pesonal Finance Tool (MyFinx)

I want to manage my saving accounts, interest rates, stock etc. in one tool.
It should be accessible from a clud e.g. render.com.
Confidential Data like IBAN, Asset names, Asset ISIN/WKN, should be end-to-end encrypted.
Registration via one time token.
Login via passkey.
No passwords should be stored.

### IN PROGRESS
+ TagsEntity make already available Tags reusable, currently every new or edited tag is stored

### DONE
+ register for passkey login with e-mail verification
+ passkey login
+ base data model with accounts, deposits, postings, interest rates, owners/groups
+ mode, jpa tests
+ devel mode: relaxed security settings, command runner for data initialization
+ accounts add view
+ user who can manage the account
+ manage owners/groups
+ edit account
+ delete account
+ savings/deposits list
+ savings/deposits add
+ savings/deposits delete
+ BUG: Add first Deposit to an empty Deposits list
+ posts list
+ give post a name
+ posts add
+ posts delete
+ allow adding new posts iff the user is in owners of from and to accounts
+ posts edit
+ savings/deposits edit
+ BUG: Deposit Edit: after removing a posting from deposit, it is imposible to add it anew.
+ BUG: Post Edit: error message on some posts, probably after editing a deposit wir deleteing a post
  
### TODO
+ check if permission for adding, deleting and editing of posts, deposits, interests, owners is correct (matches the ownershaft of the respective accounts)
+ posts add: account selection put icome and spending accounts on top of the list
+ sort/filter posts
+ sort/filter accounts
+ sort/filter deposits
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
