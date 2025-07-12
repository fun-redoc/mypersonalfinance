function getEncKey() {
    const username = document.getElementById('inpKeyPasswd').dataset.username
    const storageKey = 'enc.key.' + username;
    const password = sessionStorage.getItem(storageKey); // TODO find a more secure way to temporarilly save the encryption key,
                                                         // this is only for convenience, to avoid that the user has to type in the
                                                         // everey time he accesses an accounts encrypted data
    return password;
}

document.addEventListener('DOMContentLoaded', async () => {

    document.getElementById('btnCancel')
          .addEventListener('click', (evt) => {
            const form = document.getElementById('formAccount');
            form.reset();
            window.location.replace("/accounts");
          });

    document.getElementById('btnOpenNewAccountModal')
          .addEventListener('click', (evt) => {
            // TODO I'm accessing element IDs from the fragment of settings.html here, not the most nice ways, but
            //      move the fragment to fragments.html for more transparency
            const form = document.getElementById('formAccount');
            //const username = document.getElementById('inpKeyPasswd').dataset.username
            //const storageKey = 'enc.key.' + username;
            //const password = sessionStorage.getItem(storageKey); // TODO find a more secure way to temporarilly save the encryption key,
            //                                                     // this is only for convenience, to avoid that the user has to type in the
            //                                                     // everey time he accesses an accounts encrypted data
            const password = getEncKey();
            if(password) {
              form.reset();
              toggleModal(evt);
            } else {
                const keyEntryDialog = document.getElementById('keyEntry');
                const btnCreateKey = document.getElementById('btnCreateKey');
                btnCreateKey.addEventListener('click', async () => {
                    const that = this;
                      btnCreateKey.removeEventListener('click', that);
                      closeModal(keyEntryDialog);
                      form.reset();
                      toggleModal(evt);
                });
                openModal(keyEntryDialog);
            }
          });

  document.getElementById('btnSubmitAccount')
          .addEventListener('click' , async (evt)=>{
           const ibanElem = document.getElementById('iban');
           const plain = ibanElem.value;
           const password = getEncKey();
           var encryptedIBAN = await AES().encrypt(plain,password);
           ibanElem.dataset.encrypted = encryptedIBAN;
           const form = document.getElementById('formAccount');
           form.submit();
          });

  const form = document.getElementById('formAccount');
  form.addEventListener('formdata', async (evt) => {
    // perform the encryption within the onchange handler of the input element
    // because encryption is promise based we cannot use it in this (syncronous) handler, unfortunatelly
    const encIban = document.getElementById('iban').dataset.encrypted;
    // TODO check if encIban is empty and handle error in this case (should rather not happen)
    evt.formData.set('iban', encIban);
  });

  const password = getEncKey();
  if(password) {
    const elemIban = document.getElementById('iban')
    if(elemIban.dataset.encrypted) {
      var plainIBAN = await AES().decrypt(elemIban.dataset.encrypted,password);
      elemIban.value = plainIBAN;
    }
  } else {
      const keyEntryDialog = document.getElementById('keyEntry');
      const btnCreateKey = document.getElementById('btnCreateKey');
      btnCreateKey.addEventListener('click', async () => {
          const that = this;
          btnCreateKey.removeEventListener('click', that);
          closeModal(keyEntryDialog);
          const elemIban = document.getElementById('iban')
          if(elemIban.dataset.encrypted) {
            const password = getEncKey();
            var plainIBAN = await AES().decrypt(elemIban.dataset.encrypted,password);
            elemIban.value = plainIBAN;
          }
      });
      openModal(keyEntryDialog);
  }

//    const elemIban = document.getElementById('iban')
//    if(elemIban.dataset.encrypted) {
//      const password = getEncKey();
//      var plainIBAN = await AES().decrypt(elemIban.dataset.encrypted,password);
//      elemIban.value = plainIBAN;
//    }
});