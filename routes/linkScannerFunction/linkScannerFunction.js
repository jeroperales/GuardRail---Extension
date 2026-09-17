
const button = document.getElementById('backButton');

const input = document.getElementById('linkInput')  //RECIEVES FROM HTML LINK THAT WAS INPUTED
const scanButton = document.getElementById('scanBtn') 
const resultBox = document.getElementById('resultBox') //Sends feed back to HTML and updates the result box 
const resultText = document.getElementById('resultText'); //


button.addEventListener("click", () => {
    
  window.location.href = "/popup.html";

}); 