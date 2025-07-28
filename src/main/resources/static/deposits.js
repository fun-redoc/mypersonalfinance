// helper for creating typed objects
// needed for more relieable sorting of rows
const constructorFor = (type) => {
    switch(type) {
      case "date": return (val) => new Date(val);
      case "number": return (val) => new Number(val);
      default: return (val) => val;
    }
};

document.addEventListener('DOMContentLoaded', () => {

    // event listener for sorting the deposit table
    const table = document.getElementById('deposits-table');
    const headers = table.querySelectorAll('th[data-key]');
    headers.forEach(header => {
      header.addEventListener('click', () => {
        headers.forEach(otherHeader => {
          // headers which are not subject to sort now
          // remove the sort marker
          if(otherHeader!==header) {
            otherHeader.classList.remove('asc');
            otherHeader.classList.remove('desc');
          }
        });

        // handle flipping of the sort direction indicator
        if(header.classList.contains('asc')) {
          header.classList.remove('asc');
          header.classList.add('desc'); // For descending sort
        } else {
          header.classList.remove('desc');
          header.classList.add('asc'); // For ascending sort
        }

        const rows = Array.from(table.querySelectorAll('tbody tr'));
        const key = header.getAttribute('data-key');
        const keyType = header.getAttribute('data-type');
        const constructor = constructorFor(keyType);

        // helper function for correct sorting direction
        // depending on sort direction setting
        let fnCompare = header.classList.contains('desc') ?
                        (a,b) => b - a:
                        (a,b) => a - b;

        const sortedRows = rows.sort((a, b) => {
          // select the columns to compare
          const aCol = a.querySelector(`td[data-key="${key}"]`);
          const bCol = b.querySelector(`td[data-key="${key}"]`);
          // get the value stored in data-value attribute
          // REMARK: the data-value attribute to store the sort value is redundant to the cell content, but
          //         it is going to pay of if the cell content is going to be formated in future, i
          //         dont want to rely on the visual representation
          const aColVal = aCol.dataset.value;
          const bColVal = bCol.dataset.value;
          // construct the appropriate js data type
          const aValue = constructor(aColVal);
          const bValue = constructor(bColVal);
          // compare
          return fnCompare(aValue,bValue);
        });
        sortedRows.forEach(row => table.querySelector('tbody').appendChild(row));
      });
    });

    // event listener for filter the currently valid deposits
    document.getElementById('chkShowOnlyCurrent').addEventListener('change', function() {
        const isChecked = this.checked;
        const depositRows = document.querySelectorAll('.deposit-row');
        depositRows.forEach((r,i)=>{
          const isCurrent = (r.dataset.iscurrent == 'true');
          if(!isCurrent) {
            r.hidden = isChecked;
          } else {
            r.hidden = false;
          }
        });
    });

    // button click on new Deposit button
    document.getElementById('btnNewDeposit').addEventListener('click', function() {
        const isChecked = document.getElementById('chkShowOnlyCurrent').checked;
        const url = new URL(window.location.href + '/new');
        //    url.searchParams.set('showOnlyCurrent', isChecked ? 'yes' : 'no');
        window.location.href = url; // Navigate to the updated URL
    });

});