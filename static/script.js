document.addEventListener("DOMContentLoaded", () => {
  fetchTelemetry();

  // Enter key press karne par direct report search trigger karne ke liye
  const inputEl = document.getElementById("custom-log-input");
  if (inputEl) {
    inputEl.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        analyzeCustomInput();
      }
    });
  }
});

async function fetchTelemetry() {
  const tbody = document.getElementById("incidents-body");

  try {
    const response = await fetch("/api/incidents");
    if (!response.ok) {
      throw new Error(`HTTP status ${response.status}`);
    }

    const data = await response.json();

    const metrics = data.metrics || {
      total_logs: 0,
      total_incidents: 0,
      malicious_actors: 0,
      unique_ips: 0,
    };

    const incidents = data.incidents || [];

    document.getElementById("total-logs").innerText = metrics.total_logs;
    document.getElementById("total-threats").innerText =
      metrics.total_incidents;
    document.getElementById("malicious-actors").innerText =
      metrics.malicious_actors;
    document.getElementById("unique-ips").innerText = metrics.unique_ips;

    if (incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #94a3b8; padding: 24px;">No security incidents detected. Log clean.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map((item) => createRowHTML(item)).join("");
  } catch (err) {
    console.error("Telemetry parsing error:", err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #ef4444; padding: 24px;">Error connecting to telemetry pipeline: ${err.message}</td></tr>`;
  }
}

function createRowHTML(item) {
  const score = item.score ?? 0;
  let badgeClass = "badge-benign";
  let severityLabel = (item.severity || "LOW").toUpperCase();

  if (severityLabel === "CRITICAL" || score >= 80) {
    badgeClass = "badge-critical";
    severityLabel = "CRITICAL";
  } else if (severityLabel === "HIGH" || score >= 40) {
    badgeClass = "badge-high";
    severityLabel = "HIGH";
  }

  return `
    <tr>
      <td class="code-text">${item.ip || "Unknown"}</td>
      <td><span class="badge-country">${item.country || "N/A"}</span></td>
      <td><strong>${item.attack_type || "Suspicious Activity"}</strong></td>
      <td class="code-text" style="color: #94a3b8;">${item.endpoint || "/"}</td>
      <td>
        <span style="font-family: 'JetBrains Mono'; font-weight: 700; color: ${score > 50 ? "#ef4444" : "#10b981"};">
          ${score}%
        </span>
      </td>
      <td><span class="badge-severity ${badgeClass}">${severityLabel}</span></td>
    </tr>
  `;
}

function analyzeCustomInput() {
  const inputEl = document.getElementById("custom-log-input");
  const rawText = inputEl ? inputEl.value.trim() : "";
  const btn = document.getElementById("btn-analyze");

  if (!rawText) {
    alert("Please enter a website URL, domain, or IP address to inspect.");
    return;
  }

  if (btn) {
    btn.innerText = "OPENING REPORT...";
    btn.style.opacity = "0.7";
  }

  // Dedicated Audit Report Page par redirect karega
  window.location.href = `/report?target=${encodeURIComponent(rawText)}`;
}
