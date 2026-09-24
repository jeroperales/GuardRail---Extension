
const button = document.getElementById('backButton');

const input = document.getElementById('linkInput')  //RECIEVES FROM HTML LINK THAT WAS INPUTED
const scanButton = document.getElementById('scanBtn') 
const resultBox = document.getElementById('resultBox') //Sends feed back to HTML and updates the result box 
const resultText = document.getElementById('resultText'); // same thing as result but text

scanButton.addEventListener('click', async ()=> {

  const link = input.value.trim(); //recieves link and trims any excess in pasted link
  
  const userInput = {
  url: link
}

  if(!link) {
    showResult('Please paste a link first. ');
    return;
  }  

  showResult ('Analyzing..'); 

 try {
    const response = await fetch("http://127.0.0.1:5050/scan/", {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userInput)
    });
    // if error return error text else send valid json with data 
    if (!response.ok){
      data = await response.text() //Returns a string stating the user input an invalid url 
      displayVerdict(data)
    }else{
      const data = await response.json(); // Returns : True or False OR object returning an object
      displayVerdict(data); 
    }

  } catch (error) {
    showResult('Could not reach the scanner. Try again.', 'danger');
    console.error('Scan failed:', error);
  }

})

function displayVerdict(verdict) {
  if (verdict === false){
    message = "No suspicious activity detected, his site is safe to visit"
  }else if (verdict === true) {
    message = "WAIT THIS SITE IS SUSPECTED TO BE MALICIOUS PROCEEED WITH CAUTION"
  }else{
    message = "Uh oh! the URL you entered may be invalid please try again"
  }
  showResult(message);
}

function showResult(message) {
  resultText.textContent = message;
  resultBox.classList.remove('hidden', 'safe', 'suspicious', 'dangerous', 'warning', 'loading');
}


//RETURN BUTTON
button.addEventListener("click", () => {
    
  window.location.href = "/popup.html";

}); 
