document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('jokeButton');
    button.addEventListener('click', () => {
        fetch('/joke')
            .then(response => response.text())
            .then(data => {
                document.getElementById('jokeContainer').innerHTML = data;
            });
    });
});

