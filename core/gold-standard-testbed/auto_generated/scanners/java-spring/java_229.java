// Vulnerable: JAVA-229
got('http://api.nasa.gov/planetary/apod?api_key=DEMO_KEY', { json: true }).then(response => {
    console.log(response.body.url);
    console.log(response.body.explanation);
    }).catch(error => {
    console.log(error.response.body);
    });
}
