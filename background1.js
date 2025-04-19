chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed");
});

// Listen for page load completion
chrome.webNavigation.onCompleted.addListener((details) => {
  const currentUrl = details.url;
  console.log("Navigation detected:", currentUrl);

  // Only show a notification if the status is 'complete' and it's not a redirect
  if (details.frameId === 0) {  // Only for top-level frames (main page)
    // Check the URL for issues
    const issues = checkUrl(currentUrl);

    // Log the detected issues
    console.log("Detected Issues:", issues);  // Debugging the issues

    // If there are issues, show them in one notification
    if (issues.length > 0) {
      showNotification(`Issues detected:\n${issues.join("\n")}`, true);
    } else {
      // If everything is fine, send a success notification
      showNotification("Everything looks good!", false);
    }
  }
}, { url: [{ schemes: ['http', 'https'] }] });  // Ensure this works only for HTTP/HTTPS pages

// Function to check the URL for issues
function checkUrl(urlString) {
  const url = new URL(urlString);
  const issues = [];


  // Check for too many subdomains
  if (url.hostname.split('.').length > 3) {
    issues.push("The site has too many subdomains.");
  }

  // Check for suspicious characters
  if (/[#@\$%]/.test(url.href)) {
    issues.push("The site has suspicious characters.");
  }

  // Check if the URL is too long
  if (url.href.length > 300) {
    issues.push("The URL is too long.");
  }

  // Check if the site is from a malicious country
  if (isMaliciousCountry(url.hostname)) {
    issues.push("The site is from a malicious country.");
  }

  // Return the issues array
  return issues;
}

// Function to check if the country is a malicious country based on TLD or domain suffix
function isMaliciousCountry(hostname) {
  const maliciousCountries = ['.eg', '.ps', '.tr', '.iq', '.ir', '.ye', '.lb', '.sy', '.kp'];  // Added North Korea (.kp)
  for (const country of maliciousCountries) {
    if (hostname.endsWith(country)) {
      return true;
    }
  }
  return false;
}

// Function to show a notification
function showNotification(message, isMalicious) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "/icon.png", // Ensure this path is correct and icon exists
    title: isMalicious ? "Warning: URL Issues" : "URL Check Passed",
    message: message,
    priority: 2, // Set the priority to ensure it shows prominently
  });
}
