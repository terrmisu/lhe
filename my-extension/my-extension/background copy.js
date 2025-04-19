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
            showNotification(`VirusTotal Warning:\n${vtResult}`, true);
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


// Listen for file downloads and check before allowing them
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const fileUrl = downloadItem.url;
  console.log(`File download detected: ${fileUrl}`);

  // Run local file safety checks
  const isMalicious = checkLocalFile(fileUrl);
  if (isMalicious) {
      console.warn(`⚠️ Malicious file detected: ${fileUrl}`);
      showNotification(`⚠️ Malicious File Detected:\n${fileUrl}`, true);
      chrome.downloads.cancel(downloadItem.id, () => {
          console.log("Download canceled due to potential threat.");
      });
  } else {
      // Scan file with HybridAnalysis
      const isThreat = await scanFileWithHybridAnalysis(fileUrl);
      if (isThreat) {
          console.warn(`⚠️ HybridAnalysis detected a threat: ${fileUrl}`);
          showNotification(`⚠️ HybridAnalysis Threat Detected:\n${fileUrl}`, true);
          chrome.downloads.cancel(downloadItem.id, () => {
              console.log("Download canceled due to HybridAnalysis threat detection.");
          });
      } else {
          showNotification(`✅ File is safe:\n${fileUrl}`, false);
      }
  }
});

// Scan the file with HybridAnalysis
async function scanFileWithHybridAnalysis(fileUrl) {
  try {
      const response = await fetch("https://www.hybrid-analysis.com/api/v2/submit/url", {
          method: "POST",
          headers: {
              "api-key": HYBRID_ANALYSIS_API_KEY,
              "accept": "application/json",
              "Content-Type": "application/json",
              "user-agent": "Falcon Sandbox"
          },
          body: JSON.stringify({
              "url": fileUrl,
              "environment_id": 160
          })
      });

      const result = await response.json();
      if (result.job_id) {
          console.log("File submitted to HybridAnalysis, checking results...");
          return await getHybridAnalysisResults(result.job_id);
      } else {
          console.error("HybridAnalysis submission failed:", result);
          return false;
      }
  } catch (error) {
      console.error("HybridAnalysis API Error:", error);
      return false;
  }
}

// Get HybridAnalysis scan results
async function getHybridAnalysisResults(jobId) {
  try {
      const response = await fetch(`https://www.hybrid-analysis.com/api/v2/report/${jobId}`, {
          method: "GET",
          headers: {
              "api-key": HYBRID_ANALYSIS_API_KEY,
              "accept": "application/json",
              "user-agent": "Falcon Sandbox"
          }
      });

      const result = await response.json();
      if (result.verdict === "malicious") {
      showNotification(`⚠️ HybridAnalysis detected a threat in the file.`, true);
      return true;
  } else {
      showNotification("✅ File is safe according to HybridAnalysis.", false);
      return false;
  }
  } catch (error) {
      console.error("Failed to retrieve HybridAnalysis results:", error);
      return false;
  }
}


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

// Listen for ZIP file downloads using declarativeNetRequest
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{
      "id": 1,
      "priority": 1,
      "action": { "type": "block" },
      "condition": {
          "urlFilter": "*.zip",
          "resourceTypes": ["main_frame", "sub_frame"]
      }
  }],
  removeRuleIds: [1]
}, () => {
  console.log("Blocking rule for ZIP downloads added.");
});


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

// Local file check function
function checkLocalFile(fileUrl) {
  const maliciousPatterns = ["malicious", "virus", "trojan", "phishing"];
  return maliciousPatterns.some(pattern => fileUrl.toLowerCase().includes(pattern));
}


