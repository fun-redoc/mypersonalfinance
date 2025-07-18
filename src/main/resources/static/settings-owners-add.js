/* ----- begin of: handler function definitions ----- */
function allowDrop(ev) {
    console.log("allowDrop");
  ev.preventDefault();

  document.querySelectorAll(".assignment-list.over").forEach(box =>
    box.addEventListener("dragleave", () => box.classList.remove("over"))
  );

  ev.currentTarget.classList.add("over");
}

function drag(ev) {
    console.log("drag");
  ev.dataTransfer.setData("text", ev.target.id);
}

function drop(ev) {
    console.log("drop");
  ev.preventDefault();
  const data = ev.dataTransfer.getData("text");
  const dragged = document.getElementById(data);
  ev.currentTarget.appendChild(dragged);
  ev.currentTarget.classList.remove("over");

  document.querySelectorAll(".assignment-list.over").forEach(box =>
    box.addEventListener("dragleave", () => box.classList.remove("over"))
  );
}
/* ----- end of: handler function definitions ----- */

/* ----- begin of: event handlers */
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('btnCancelOwner')
          .addEventListener('click', (evt) => {
            const form = document.getElementById('formOwner');
            form.reset();
            window.location.replace("/settings");
          });

  document.getElementById('btnSubmitOwner')
        .addEventListener('click' , async (evt)=>{
            console.log("btnSubmitOwner");
           const form = document.getElementById('formOwner');
           form.submit();
        });

  const form = document.getElementById('formOwner');
  form.addEventListener('formdata', async (evt) => {
    console.log("formdata");
    document
        .querySelectorAll('#assignedUsers > .assignment-list-item')
        .forEach( (n,i) => {
                    console.log(n.dataset.id)
                        evt.formData.append(`userIds[${i}]`, n.dataset.id);
                } )
  });
});
/* ----- end of: event handlers */
