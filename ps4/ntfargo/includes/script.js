let timerId = null;

const jeilbrekBtn = document.getElementById("jeilbrek");
const UAElement = document.getElementById("UA");

const countdownText = document.getElementById("countdown");
const checkbox = document.getElementById("autoJbInput");

// Auto JB (default OFF)
const storedAutoJb = localStorage.getItem("autoJb");
const autoJbValue = storedAutoJb !== null ? storedAutoJb === "true" : false;

// Kernel exploit
let exploitChain = localStorage.getItem("exploitChain") || "lapse";

const netctrlRadio = document.getElementById("netctrl-exploit");
const lapseRadio = document.getElementById("lapse-exploit");
const kexForm = document.getElementById("kernel-options");

// User Agent
UAElement.textContent += " " + navigator.userAgent;

// ========================================================
// Kernel Selection
// ========================================================

kexForm.addEventListener("change", function (event) {
  exploitChain = event.target.value;

  localStorage.setItem("exploitChain", exploitChain);
});

// ========================================================
// Jailbreak Button
// ========================================================

jeilbrekBtn.addEventListener("click", function () {
  stopInterval();

  jeilbrekBtn.disabled = true;

  doJb();
});

// ========================================================
// Auto Jailbreak
// ========================================================

checkbox.addEventListener("change", function () {
  localStorage.setItem("autoJb", checkbox.checked);

  if (checkbox.checked && !jeilbrekBtn.disabled) {
    jailbreakCountdown();
  } else {
    stopInterval();
  }
});

function stopInterval() {
  if (timerId !== null) {
    clearInterval(timerId);

    timerId = null;
  }

  countdownText.classList.add("hidden");
}

function jailbreakCountdown() {
  stopInterval();

  let countdown = 2;

  countdownText.classList.remove("hidden");

  countdownText.textContent = "Lancement automatique dans " + countdown + "...";

  timerId = setInterval(function () {
    countdown--;

    if (countdown >= 0) {
      countdownText.textContent = "Auto JB in " + countdown + "...";
    }

    if (countdown < 0) {
      clearInterval(timerId);

      timerId = null;

      countdownText.textContent = "Veuillez patientez SVP...";

      jeilbrekBtn.disabled = true;

      doJb();
    }
  }, 1000);
}

// ========================================================
// AppCache
// ========================================================

function cacheProgress(e) {
  const percent = Math.round((e.loaded / e.total) * 100);

  document.title = "Caching: " + percent + "%";
}

function displayCacheProgress() {
  setTimeout(function () {
    document.title = "✓";
  }, 1000);

  setTimeout(function () {
    document.title = "PS4 CSSFontFace Exploit";
  }, 3000);
}

// ========================================================
// Startup
// ========================================================

document.addEventListener("DOMContentLoaded", function () {
  // AppCache

  if (window.applicationCache) {
    window.applicationCache.addEventListener("progress", cacheProgress, false);

    window.applicationCache.oncached = displayCacheProgress;

    window.applicationCache.onupdateready = displayCacheProgress;
  }

  // Selected exploit

  if (exploitChain === "netctrl") {
    netctrlRadio.checked = true;
  } else {
    lapseRadio.checked = true;
  }

  // Auto JB

  checkbox.checked = autoJbValue;

  if (autoJbValue) {
    jailbreakCountdown();
  }
});

// ========================================================
// Background Console Auto Scroll
// ========================================================

const consoleElement = document.getElementById("console");

if (consoleElement) {
  const observer = new MutationObserver(function () {
    consoleElement.scrollTop = consoleElement.scrollHeight;
  });

  observer.observe(consoleElement, {
    childList: true,

    characterData: true,

    subtree: true,
  });
}
