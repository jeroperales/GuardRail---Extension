
const button = document.getElementById('backButton');

const input = document.getElementById('linkInput')  //RECIEVES FROM HTML LINK THAT WAS INPUTED
const scanButton = document.getElementById('scanBtn') 
const resultBox = document.getElementById('resultBox') //Sends feed back to HTML and updates the result box 
const resultText = document.getElementById('resultText'); // same thing as result but text

scanButton.addEventListener('click', async ()=> {

  const link = input.value.trim(); //recieves link and trims any excess in pasted link

  if(!link) {
    showResult('Please paste a link first. ', 'warning');
    return;
  }  

  showResult ('Analyzing... ', 'loading'); 

 try {
    //SEND THE BACK END THE LINK COPIED

      throw new Error('TEST ERROR');

  } catch (error) {
    showResult('Could not reach the scanner. Try again.', 'danger');
    console.error('Scan failed:', error);
  }

})

function displayVerdict(data) {
  const messages = {
    safe: ` This link looks safe. ${data.reason || ''}`,
    suspicious: ` This link looks suspicious. ${data.reason || ''}`,
    dangerous: ` This link is likely dangerous. ${data.reason || ''}`
  };

  const level = data.safety || 'suspicious';
  showResult(messages[level], level);
}

function showResult(message, type) {
  resultText.textContent = message;
  resultBox.classList.remove('hidden', 'safe', 'suspicious', 'dangerous', 'warning', 'loading');
  resultBox.classList.add(type);
}


//RETURN BUTTON
button.addEventListener("click", () => {
    
  window.location.href = "/popup.html";

}); 