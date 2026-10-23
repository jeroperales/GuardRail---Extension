
const phishInput = document.getElementById('phishInput')  //RECIEVES FROM HTML LINK THAT WAS INPUTED
const phishScanButton = document.getElementById('phishBtn') 
const phishResultBox = document.getElementById('phishResultBox') //Sends feed back to HTML and updates the result box 
const phishResultText = document.getElementById('phishResultText'); // same thing as result but text


phishScanButton.addEventListener('click', async ()=> {
  const phishText = phishInput.value.trim();

  const phishUserInput = {
    text: phishText
  }

  if (!phishText){
    phishShowResult('Please input text')
    return
  }

    phishShowResult('Analyzing Text...')

  try {
    const response = await fetch("http://127.0.0.1:5050/scantext/", {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(phishUserInput)
    })

    const data = await response.json()
    phishScore = 0 
    if (data.label != 'phishing'){
      phishScore = 1 - data.score
    }else{
      phishScore = data.score
    }
    phishShowResult(`Phishing likelihood: ${(phishScore * 100).toFixed(1) }%`)
  
  } catch(error){
    phishShowResult('Could not reach the scanner. Try again.', 'danger');
    console.log(error)
  }

})

function phishShowResult(message){
  phishResultText.textContent = message;
  phishResultBox.classList.remove('hidden', 'safe', 'suspicious', 'dangerous', 'warning', 'loading');
}

