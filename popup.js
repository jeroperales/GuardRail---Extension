
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
    console.error('failed:', error);
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
if (button) {
  button.addEventListener("click", () => {
    window.location.href = "/popup.html";
  });
}



// ===== FILE SCANNER =====
const SCAN_URL = "http://127.0.0.1:8000/file";   // matches @app.post("/file")
const MAX_FILE_SIZE = 32 * 1024 * 1024;
const SCAN_TIMEOUT_MS = 180000;

const fileInput = document.getElementById("fileInput");
const fileScanBtn = document.getElementById("fileScanBtn");
const fileResultBox = document.getElementById("fileResultBox");
const fileResultText = document.getElementById("fileResultText"); // hidden by CSS; the card replaces it
const dropzone = document.querySelector(".dropzone");
const dropMain = dropzone.querySelector(".dropMain");
const dropSub = dropzone.querySelector(".dropSub");
const DROP_MAIN_DEFAULT = dropMain.textContent;
const DROP_SUB_DEFAULT = dropSub.innerHTML;

// verdict -> look, headline, and plain-language advice
const VERDICTS = {
    malicious:        { tone: "danger",  icon: "✕", title: "Dangerous file",
                        advice: "Do not open this file. Delete it, and don't forward it to anyone." },
    suspicious:       { tone: "warn",    icon: "!", title: "Suspicious file",
                        advice: "Some engines flagged this file. Only open it if you fully trust the sender, and ideally not at all." },
    no_threats_found: { tone: "safe",    icon: "✓", title: "No threats found",
                        advice: "No engine flagged this file. That's a good sign, but no scan can guarantee a file is safe." },
    inconclusive:     { tone: "warn",    icon: "?", title: "Inconclusive",
                        advice: "Too many engines didn't respond to trust a clean result. Treat the file as unverified and scan it again later." },
    pending:          { tone: "loading", icon: "…", title: "Still analyzing",
                        advice: "The analysis is still running. Wait a minute and scan again." },
    not_found:        { tone: "neutral", icon: "?", title: "Not found",
                        advice: "This file has never been scanned before." },
    error:            { tone: "neutral", icon: "!", title: "Scan error",
                        advice: "The scan could not be completed. Nothing was concluded about this file." },
};

// ----- small helpers (all text goes through textContent, never innerHTML) -----
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatElapsed(totalSeconds) {
    const s = Math.floor(totalSeconds);
    return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function buildHead(icon, title, message) {
    const head = el("div", "scanHead");
    const badge = el("div", "scanBadge");
    badge.append(icon);
    const text = el("div", "scanHeadText");
    text.append(el("div", "scanTitle", title), el("div", "scanMessage", message));
    head.append(badge, text);
    return head;
}

function mountCard(card) {
    fileResultBox.querySelector(".scanCard")?.remove();
    fileResultBox.classList.remove("hidden", "safe", "suspicious", "dangerous", "warning", "loading");
    fileResultBox.classList.add("hasCard");
    fileResultBox.setAttribute("aria-live", "polite");
    fileResultBox.append(card);
}

function showNotice(tone, icon, title, message) {
    const card = el("div", "scanCard");
    card.dataset.tone = tone;
    card.append(buildHead(icon, title, message));
    mountCard(card);
}

// ----- scanning (loading) card with a live timer -----
function showScanning(file) {
    const card = el("div", "scanCard");
    card.dataset.tone = "loading";
    card.append(buildHead(el("span", "scanSpinner"), "Scanning…", file.name));

    const bar = el("div", "scanBar indeterminate");
    bar.append(el("div", "scanBarFill"));
    const timer = el("div", "scanTimer", "Elapsed 0:00");
    const note = el("div", "scanNote",
        "Files VirusTotal has already seen return quickly. New files are queued and can take up to 2 minutes.");
    card.append(bar, timer, note);
    mountCard(card);

    const started = Date.now();
    const id = setInterval(() => {
        timer.textContent = `Elapsed ${formatElapsed((Date.now() - started) / 1000)}`;
    }, 500);
    return () => clearInterval(id);   // call to stop the timer
}

// ----- the verdict card -----
function stat(value, label) {
    const box = el("div", "scanStat");
    box.append(el("div", "scanStatValue", value), el("div", "scanStatLabel", label));
    return box;
}

function infoRow(label, value) {
    const row = el("div", "scanRow");
    row.append(el("span", "scanLabel", label), el("span", "scanValue", value));
    return row;
}

function renderScanResult(data, file) {
    const v = VERDICTS[data.verdict] || VERDICTS.error;
    const card = el("div", "scanCard");
    card.dataset.tone = v.tone;
    card.append(buildHead(v.icon, v.title, data.message));

    // numbers + coverage meter (only when engines actually ran)
    if (data.engines_total > 0) {
        const stats = el("div", "scanStats");
        stats.append(
            stat(String(data.detections), "Detections"),
            stat(`${data.engines_completed}/${data.engines_total}`, "Engines responded"),
            stat(`${data.coverage_pct}%`, "Coverage")
        );
        card.append(stats);

        const meter = el("div", "scanBar");
        const fill = el("div", "scanBarFill");
        fill.style.width = `${Math.max(0, Math.min(100, data.coverage_pct))}%`;
        meter.append(fill);
        card.append(meter);
    }

    // which engines flagged it
    if (data.flagged_by && data.flagged_by.length) {
        const wrap = el("div", "scanFlagged");
        wrap.append(el("div", "scanLabel", "Flagged by"));
        const chips = el("div", "scanChips");
        data.flagged_by.forEach(name => chips.append(el("span", "scanChip", name)));
        wrap.append(chips);
        card.append(wrap);
    }

    // file details
    const info = el("div", "scanInfo");
    if (file) {
        info.append(infoRow("File", file.name), infoRow("Size", formatBytes(file.size)));
    }
    if (data.sha256) {
        const row = el("div", "scanRow");
        row.append(el("span", "scanLabel", "SHA-256"));
        const shown = `${data.sha256.slice(0, 12)}…${data.sha256.slice(-8)}`;
        const hash = el("span", "scanValue scanHash", shown);
        hash.title = data.sha256;
        const copy = el("button", "scanCopy", "Copy");
        copy.type = "button";
        copy.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(data.sha256);
                copy.textContent = "Copied";
            } catch {
                copy.textContent = "Failed";
            }
            setTimeout(() => (copy.textContent = "Copy"), 1500);
        });
        row.append(hash, copy);
        info.append(row);
    }
    card.append(info);

    card.append(el("p", "scanAdvice", v.advice));

    // actions
    const actions = el("div", "scanActions");
    if (data.report_url && data.report_url.startsWith("https://www.virustotal.com/")) {
        const link = el("a", "scanLink", "View full report");
        link.href = data.report_url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        actions.append(link);
    }
    const again = el("button", "scanAgain", "Scan another file");
    again.type = "button";
    again.addEventListener("click", () => {
        fileInput.value = "";
        updateFileName();   // also hides the result box
    });
    actions.append(again);
    card.append(actions);

    mountCard(card);
}

// ----- file selection + validation -----
function validateFile(file) {
    if (!file) return "Please select a file first.";
    if (file.size === 0) return "That file is empty.";
    if (file.size > MAX_FILE_SIZE) return `That file is ${formatBytes(file.size)}. The limit is 32 MB.`;
    return null;
}

function updateFileName() {
    const f = fileInput.files[0];
    dropMain.textContent = f ? f.name : DROP_MAIN_DEFAULT;
    if (f) dropSub.textContent = `${formatBytes(f.size)} · click to choose a different file`;
    else dropSub.innerHTML = DROP_SUB_DEFAULT;
    fileResultBox.classList.add("hidden");   // a new selection clears the old verdict
}

fileInput.addEventListener("change", () => {
    updateFileName();
    const problem = validateFile(fileInput.files[0]);
    if (fileInput.files[0] && problem) showNotice("warn", "!", "Can't scan this file", problem);
});

// ----- drag & drop -----
let dragDepth = 0;   // dragenter/dragleave also fire for child elements, so count them

dropzone.addEventListener("dragenter", e => {
    e.preventDefault();
    dragDepth++;
    dropzone.classList.add("dragover");
});
dropzone.addEventListener("dragover", e => {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
});
dropzone.addEventListener("dragleave", e => {
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropzone.classList.remove("dragover");
});
dropzone.addEventListener("drop", e => {
    e.preventDefault();
    dragDepth = 0;
    dropzone.classList.remove("dragover");

    const dt = e.dataTransfer;
    if (!dt || !dt.files.length) return;

    const entry = dt.items?.[0]?.webkitGetAsEntry?.();
    if (entry?.isDirectory) {
        showNotice("warn", "!", "Folders aren't supported", "Drop a single file, or zip the folder first.");
        return;
    }

    // keep only the first file and hand it to the real <input> so the scan code has one source of truth
    const picked = new DataTransfer();
    picked.items.add(dt.files[0]);
    fileInput.files = picked.files;
    updateFileName();

    const problem = validateFile(fileInput.files[0]);
    if (problem) {
        showNotice("warn", "!", "Can't scan this file", problem);
    } else if (dt.files.length > 1) {
        showNotice("neutral", "i", "One file at a time",
            `Selected ${dt.files[0].name}. The other ${dt.files.length - 1} file(s) were ignored.`);
    }
});

// stop the browser from navigating to a file dropped outside the dropzone
["dragover", "drop"].forEach(evt =>
    window.addEventListener(evt, e => e.preventDefault())
);

// ----- scan -----
fileScanBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];

    const problem = validateFile(file);
    if (problem) {
        showNotice("warn", "!", "Can't scan this file", problem);
        return;
    }

    const formData = new FormData();
    formData.append("upload", file);   // must match the FastAPI parameter name

    fileScanBtn.disabled = true;
    const stopTimer = showScanning(file);

    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    try {
        const response = await fetch(SCAN_URL, {
            method: "POST",
            body: formData,
            signal: controller.signal
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            const detail = typeof data?.detail === "string" ? data.detail : `Server error (${response.status}).`;
            showNotice("neutral", "!", "Scan failed", detail);
            return;
        }
        if (!data || !data.verdict) {
            showNotice("neutral", "!", "Scan error", "The server sent back something unexpected.");
            return;
        }
        renderScanResult(data, file);

    } catch (error) {
        if (error.name === "AbortError") {
            showNotice("neutral", "!", "Scan timed out", "The scan took too long. Please try again.");
        } else {
            showNotice("neutral", "!", "Can't reach the scanner",
                "Is the server running? Start it, then try again.");
        }
        console.error("File scan failed:", error);
    } finally {
        stopTimer();
        clearTimeout(abortTimer);
        fileScanBtn.disabled = false;
    }
});

// ----- DEV ONLY: preview every verdict without the server. Delete before shipping. -----
// In the console, run: previewVerdict("malicious")
window.previewVerdict = (name) => {
    const fakeHash = "a".repeat(64);
    const base = { sha256: fakeHash, report_url: `https://www.virustotal.com/gui/file/${fakeHash}` };
    const samples = {
        malicious: { ...base, verdict: "malicious", message: "41 engines flagged this file as malicious.",
                     detections: 41, engines_completed: 66, engines_total: 70, coverage_pct: 94.3,
                     flagged_by: ["Engine A", "Engine B", "Engine C", "Engine D"] },
        suspicious: { ...base, verdict: "suspicious", message: "Some engines flagged this file. Treat with caution.",
                      detections: 2, engines_completed: 62, engines_total: 70, coverage_pct: 88.6,
                      flagged_by: ["Engine A", "Engine B"] },
        no_threats_found: { ...base, verdict: "no_threats_found", message: "No threats detected by the scanning engines.",
                            detections: 0, engines_completed: 64, engines_total: 68, coverage_pct: 94.1, flagged_by: [] },
        inconclusive: { ...base, verdict: "inconclusive",
                        message: "No detections, but only 28 of 64 engines completed. Rescan later.",
                        detections: 0, engines_completed: 28, engines_total: 64, coverage_pct: 43.8, flagged_by: [] },
        pending: { verdict: "pending", message: "Analysis is taking longer than expected. Try again in a minute.",
                   detections: 0, engines_completed: 0, engines_total: 0, coverage_pct: 0, flagged_by: [] },
        not_found: { verdict: "not_found", message: "File has not been scanned before.",
                     detections: 0, engines_completed: 0, engines_total: 0, coverage_pct: 0, flagged_by: [] },
        error: { verdict: "error", message: "Scan service rate limit reached. Try again shortly.",
                 detections: 0, engines_completed: 0, engines_total: 0, coverage_pct: 0, flagged_by: [] },
    };
    if (!samples[name]) return console.log("Options:", Object.keys(samples).join(", "));
    renderScanResult(samples[name], { name: "invoice_2026.exe.pdf", size: 482113 });
};