chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension installed");
    // Store the API key securely
    chrome.storage.local.set({ vt_api_key: "3d01f9c15e634dbb34370797c75f4ccc431ea5b1842027538b72c8267b85aa82" }, () => {
        console.log("VirusTotal API Key saved securely.");
    });
  });
  
  // Listen for page load completion
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId === 0) { // Only for top-level frames (main page)
        const currentUrl = details.url;
        console.log("Navigation detected:", currentUrl);
        
        // Check with VirusTotal
        const vtResult = await checkWithVirusTotal(currentUrl);
        console.log("VirusTotal Check Result:", vtResult);
        
        if (!vtResult || vtResult === "VirusTotal check failed." || vtResult === "VirusTotal scan is still in progress. Try again later.") {
            console.error("Failed to retrieve valid VirusTotal results.");
            showNotification("VirusTotal check failed or incomplete.", true);
            return; // Stop execution if VirusTotal fails
        }

        if (vtResult.includes("malicious") || vtResult.includes("suspicious")) {
            showNotification(`⚠️ VirusTotal Warning:\n${vtResult}`, true);
            return; // Stop execution if VirusTotal detects threats
        }

        // If VirusTotal passes, run local URL check
        setTimeout(() => {
            const issues = checkUrl(currentUrl);
            console.log("Detected Issues:", issues);

            if (issues.length > 0) {
                showNotification(`Issues detected:\n${issues.join("\n")}`, true);
            } else {
                showNotification("Everything looks good!", false);
            }
        }, 5000); // Delay to allow VirusTotal check to complete first
    }
}, { url: [{ schemes: ['http', 'https'] }] });

  
  // Retrieve API Key
  async function getApiKey() {
    return new Promise((resolve) => {
        chrome.storage.local.get("vt_api_key", (result) => {
            resolve(result.vt_api_key || null);
        });
    });
  }
  
  // Send URL to VirusTotal for scanning
  async function checkWithVirusTotal(url) {
    const apiKey = await getApiKey();
    if (!apiKey) {
        console.error("VirusTotal API Key is missing!");
        return "VirusTotal API Key is missing!";
    }
  
    const endpoint = "https://www.virustotal.com/api/v3/urls";
  
    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "x-apikey": apiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        });
  
        if (!response.ok) throw new Error(`Failed to send URL to VirusTotal: ${response.status} ${await response.text()}`);
  
        const result = await response.json();
        const analysisId = result.data.id;
  
        return await getVirusTotalAnalysis(analysisId, apiKey);
    } catch (error) {
        console.error("VirusTotal Error:", error);
        return "VirusTotal check failed.";
    }
  }
  
  // Retrieve the analysis results
  async function getVirusTotalAnalysis(analysisId, apiKey) {
    const url = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
  
    try {
        let attempts = 0;
        while (attempts < 10) { // Increase retry attempts to allow more time for scanning
            const response = await fetch(url, {
                method: "GET",
                headers: { "x-apikey": apiKey }
            });
  
            if (!response.ok) throw new Error(`Failed to retrieve VirusTotal results: ${response.status} ${await response.text()}`);
  
            const result = await response.json();
            if (result.data.attributes.status === "completed") {
                const stats = result.data.attributes.stats;
                if (stats.malicious > 0 || stats.suspicious > 0) {
                    return `Detected ${stats.malicious} malicious & ${stats.suspicious} suspicious detections.`;
                }
                return "No threats found.";
            }
  
            await new Promise(resolve => setTimeout(resolve, 5000)); // Increase delay between retries
            attempts++;
        }
        return "VirusTotal scan is still in progress. Try again later.";
    } catch (error) {
        console.error("VirusTotal Analysis Error:", error);
        return "VirusTotal check failed.";
    }
  }
  
  // Function to check the URL for issues
  function checkUrl(urlString) {
    const url = new URL(urlString);
    const issues = [];
    //add ip address check
    if (url.hostname.split('.').length > 4) {
        issues.push("The site has too many subdomains.");
    }
  
    if (/[#@\$%]/.test(url.href)) {
        issues.push("The site has suspicious characters.");
    }
  
    if (url.href.length > 300) {
        issues.push("The URL is too long.");
    }
  
    if (isMaliciousCountry(url.hostname)) {
        issues.push("The site is from a malicious country.");
    }
  
    return issues;
  }
  
  // Function to check if the country is a malicious country based on TLD or domain suffix
  function isMaliciousCountry(hostname) {
    const maliciousCountries = ['.eg', '.ps', '.tr', '.iq', '.ir', '.ye', '.lb', '.sy', '.kp'];
    return maliciousCountries.some(country => hostname.endsWith(country));
  }
  
  // Show a Chrome notification
  function showNotification(message, isMalicious) {
    chrome.notifications.create({
        type: "basic",
        iconUrl: "/icon.png",
        title: isMalicious ? "Warning: URL Issues" : "URL Check Passed",
        message: message,
        priority: 2
    });
  }
  