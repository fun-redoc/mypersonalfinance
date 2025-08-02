// make shure after loading top of the page is shown
//window.onload =  function() {
//    window.scrollTo(0,0);
//};

document.addEventListener('DOMContentLoaded', () => {


    document.getElementById('formAddDeposits').addEventListener('formdata', function(evt) {
        const tags = document.querySelectorAll('.tag')
        tags.forEach((tag,idx) => {
            //console.log(`tags[${idx}].name`)
            //console.log('tags[${idx}].name')
            //console.log("tags[${idx}].name")
            if(!isNaN(tag.dataset.id)) {
                evt.formData.append(`tags[${idx}].id`, tag.dataset.id);
            }
            evt.formData.append(`tags[${idx}].name`, tag.dataset.name);
        });
//        evt.formData.append('tags[0].id', '1');
//        evt.formData.append('tags[0].name', 'hello');
    });

    // HANDLER
    // show the input field for the appropriate interest type after selection
    document.getElementById('selectInterest').addEventListener('change', function() {
      const url = new URL(window.location.href);
      url.searchParams.set('action','interest_type');
      // TODO clear search params before setting new one, or introduce an action param..
      const form = document.getElementById('formAddDeposits');
      form.action = url;
      form.submit();
    });

    document.getElementById('idAccounts').addEventListener('change', function() {
      const form = document.getElementById('formAddDeposits');
      const url = new URL(window.location.href);
      url.searchParams.set('action', 'account');
      form.action = url;
      form.submit();
    });

    // HANDLER
    const btnAddPosting = document.getElementById('btnAddPosting')
    if(btnAddPosting) {
        btnAddPosting.addEventListener('click', function() {
          const form = document.getElementById('formAddDeposits');
          const url = new URL(window.location.href);
          url.searchParams.set('action', 'add_posting');
          form.action = url;
          form.submit();
        });
    }

    // HANDLER remove posting
    const removePostingButtons = document.querySelectorAll('.removePosting');
    removePostingButtons.forEach(b => {
        b.addEventListener('click', function(e) {
            const form = document.getElementById('formAddDeposits');
              const url = new URL(window.location.href);
              url.searchParams.set('action', 'remove_posting');
              url.searchParams.set('id', e.target.dataset.id);
              form.action = url;
              form.submit();

        });
    });

    // HANDLER
    // all reset buttons (marked by class="reset_button") should clear the form
    const form = document.getElementById('formAddDeposits');
    const resetButtons = document.querySelectorAll('.reset_button');
    resetButtons.forEach((b,i)=>{
        b.addEventListener("click", ()=>{
            form.reset();
        });
    });

    // HANDLER
    // all cancel buttons (marked by class="cancel_button") should navigate to deposits overview
    const cancelButtons = document.querySelectorAll('.cancel_button');
    cancelButtons.forEach((b,i)=>{
        b.addEventListener("click", ()=>{
            window.location.replace("/deposits");
        });
    });

    // TAGS
    // handler for adding tags
    const tagInput = document.getElementById('tagInput');
    console.log("adding tag listeners");
    tagInput.addEventListener('focusout', function(evt) {
        const txt = evt.target.value;
        if(txt) {
            const tagsContainer = document.getElementById('tags');
            const newTag = document.createElement('span');
            newTag.textContent = txt;
            newTag.className = "tag";
            newTag.dataset['id'] = null; // its new, has no ID from DB
            newTag.dataset['name'] = txt;
            newTag.addEventListener('click', function(evt) {
                evt.target.remove();
            });
            tagsContainer.insertBefore(newTag, evt.target);
            evt.target.value = "";
            evt.target.focus(); // TODO maybe in new Frame?
        }
      })
      tagInput.addEventListener('keyup', function(e) {
        // comma|enter (add more keyCodes delimited with | pipe)
        console.log("keyup");
        if (/(188|13)/.test(e.which)) {
            //e.target.trigger('focusout');
            e.target.dispatchEvent(new FocusEvent('focusout'))
        }
      });

    // Handlers for removing tags
     const tags = document.querySelectorAll('.tag');
     tags.forEach(tag => {
        tag.addEventListener('click', function(evt) {
            evt.target.remove();
        });
     });

});