document.addEventListener("DOMContentLoaded", () => {
  fetchTelemetry();
});

async function fetchTelemetry() {
  const tbody = document.getElementById("incidents-body");

  try {
    const response = await fetch("/api/incidents");
    if (!response.ok) {
      throw new Error(`HTTP status ${response.status}`);
    }

    const data = await response.json();

    // Fallbacks for data structures
    const metrics = data.metrics || {
      total_logs: 0,
      total_incidents: (data.incidents || []).length,
      malicious_actors: 0,
      unique_ips: 0,
    };

    const incidents = data.incidents || [];

    // Update Metric Cards
    document.getElementById("total-logs").innerText = metrics.total_logs ?? 0;
    document.getElementById("total-threats").innerText =
      metrics.total_incidents ?? incidents.length;
    document.getElementById("malicious-actors").innerText =
      metrics.malicious_actors ?? 0;
    document.getElementById("unique-ips").innerText = metrics.unique_ips ?? 0;

    // Render Table Rows
    if (incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #94a3b8; padding: 24px;">No security incidents detected. Log clean.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents
      .map((item) => {
        const score = item.abuse_score ?? item.threat_score ?? 0;
        let badgeClass = "badge-benign";
        let severityLabel = item.severity || "LOW";

        if (severityLabel.toUpperCase() === "CRITICAL" || score >= 80) {
          badgeClass = "badge-critical";
          severityLabel = "CRITICAL";
        } else if (severityLabel.toUpperCase() === "HIGH" || score >= 40) {
          badgeClass = "badge-high";
          severityLabel = "HIGH";
        }

        return `
        <tr>
          <td class="code-text">${item.ip || "Unknown"}</td>
          <td><span class="badge-country">${item.country || "N/A"}</span></td>
          <td><strong>${item.attack_type || item.attack_vector || "Suspicious Activity"}</strong></td>
          <td class="code-text" style="color: #94a3b8;">${item.endpoint || item.payload || "/"}</td>
          <td>
            <span style="font-family: 'JetBrains Mono'; font-weight: 700; color: ${score > 50 ? "#ef4444" : "#10b981"};">
              ${score}%
            </span>
          </td>
          <td><span class="badge-severity ${badgeClass}">${severityLabel}</span></td>
        </tr>
      `;
      })
      .join("");
  } catch (err) {
    console.error("Telemetry parsing error:", err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #ef4444; padding: 24px;">Error connecting to telemetry pipeline: ${err.message}</td></tr>`;
  }
}
