document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scan-again-btn");
  const scanStatus = document.getElementById("scan-status");

  // Placeholder click handler for "Re-Scan This Page" (Person 1 wires live API in Week 3)
  scanBtn.addEventListener("click", () => {
    scanBtn.textContent = "Scanning...";
    scanBtn.disabled = true;

    setTimeout(() => {
      scanBtn.textContent = "Re-Scan This Page";
      scanBtn.disabled = false;
      scanStatus.textContent = "✅ Page scan complete — report is up to date.";
      scanStatus.classList.remove("hidden");
    }, 600);
  });
});