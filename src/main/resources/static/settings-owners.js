/* ----- begin of: handler function definitions ----- */
function removeUserFromOwner(event, csrfToken, uid, oid) {
  event.preventDefault();
  const href=`/settings/owners/${oid}/users/${uid}`;
  fetch(href, { method: 'DELETE',
                headers: { 'X-CSRF-Token': csrfToken },
       })
        .then(response => {
          if (response.ok) {
            console.log('Entry deleted successfully!');
            // Optionally refresh or update the page
            //window.location.replace("/settings");
            window.location.reload();
          } else {
            console.error(`Error: request terminated with code: ${response.status}`);
            // TODO maybe the app should have messages in the footer (kind of status bar)
          }
        })
        .catch(error => console.error('Error:', error));
}
/* ----- end of: handler function definitions ----- */

/* ----- begin of: event handlers */
/* ----- end of: event handlers */
