document.addEventListener('DOMContentLoaded', () => {

    // button click on new Deposit button
    document.getElementById('btnNewWealth').addEventListener('click', function() {
        const url = new URL(window.location.href + '/edit');
        window.location.href = url; // Navigate to the updated URL
    });

});