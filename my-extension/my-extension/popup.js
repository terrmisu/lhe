import { checkUrl } from "./checkUrl.js";

document.getElementById('checkButton').addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value;
    const resultDiv = document.getElementById('result');
    
    if (url) {
      resultDiv.textContent = 'Checking...';
      
      // Call your checkUrl function or similar logic here
      const issues = await checkUrl(url);  // Replace with your function call
      resultDiv.textContent = issues.length > 0 
        ? `Issues detected: ${issues.join(', ')}`
        : 'The URL appears safe.';
    } else {
      resultDiv.textContent = 'Please enter a valid URL.';
    }
  });