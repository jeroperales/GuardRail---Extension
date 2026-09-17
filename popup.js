
//Users\\jaide\\documents\\workspace\\projects\\GuardRail---Extension\\apickonst button = document.getElementById('linktestButton');

  // REDIRECT HTML PAGES

//button.addEventListener("click", () => {
    
  //window.location.href = "routes/linkScannerFunction/linkScannerFunction.html";


//}); 

//fetches the backends response and allows us to use it in the backend

fetch("http://127.0.0.1:5000/scan/", {
  method: 'POST',
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    "url": "Youtube.com"
    }),
})
.then(resp => resp.json())
.then(data => {
    console.log(data)
})
  .catch(error => {
    console.error(error)
})


//fetch(" http://127.0.0.1:5000")
  //.then(res => res.json())
  //.then(data => {console.log(data.malicious)})


console.log('TEST TEST TEST')

