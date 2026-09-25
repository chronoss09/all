var launch_page = "launch.html"; // The page for Wii U users
var offramp_page = "offramp.html"; // The page for PC/Other users
var exploit_page = "exploit.html"; // The actual exploit page

function setWarning(warningText) {
    var btn = document.getElementById("launch-button");
    var btnText = document.getElementById("button-text");

    // Update button text and color
    btnText.innerText = warningText;
    btn.classList.add("btn-warning");
    
    // Set flag so the next click proceeds
    hasWarning = true;
}

function launchExploit() {
    return navigateTo(exploit_page);
}


function navigateTo(targetPage) {
    var paths = window.location.pathname.split("/");
    // Remove filename if present (index.html or empty string from trailing slash)
    if (paths[paths.length-1].indexOf(".") !== -1 || paths[paths.length-1] === "") {
        paths.pop();
    }
    paths.push(targetPage);
    window.location.pathname = paths.join("/");
}

function checkCompatibility() {
    var ua = navigator.userAgent;
    var userAgentDetails = ua.match(/\S+ \((.*?)\) .* (?:NintendoBrowser\/(\d+\.\d+\.\d+\.(\d+)\.(\w\w)))?/);
    
    // 1. Check if it's a Wii U
    if (userAgentDetails && userAgentDetails[1] === "Nintendo WiiU") {
        // It's a Wii U! Send them to the launcher/exploit prep page
        return navigateTo(launch_page);
    } 

    // 2. If it's not a Wii U, or the UA is spoofed/unrecognizable
    // Send them to the PC instructions page
    return navigateTo(offramp_page);
}