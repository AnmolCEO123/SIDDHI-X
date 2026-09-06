async function fetchSecurityData() {
  const tbody = document.getElementById("incidents-body");
  tbody.innerHTML =
    '<tr><td colspan="6" class="loading-state">Syncing threat telemetry...</td></tr>';

  try {
    const res = await fetch("/api/incidents");
    const data = await res.json();

    document.getElementById("metric-total").innerText =
      data.stats.total_threats;
    document.getElementById("metric-malicious").innerText =
      data.stats.malicious_actors;
    document.getElementById("metric-ips").innerText = data.stats.unique_ips;

    tbody.innerHTML = "";

    if (data.incidents.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6">No security anomalies detected.</td></tr>';
      return;
    }

    data.incidents.forEach((item) => {
      const verdictClass = item.verdict.toLowerCase();
      const row = document.createElement("tr");

      row.innerHTML = `
                <td><strong>${item.ip}</strong></td>
                <td>${item.country}</td>
                <td>${item.attack_type}</td>
                <td><code>${item.endpoint}</code></td>
                <td>
                    <span class="badge ${verdictClass}">
                        ${item.score}\% [${item.verdict}]
                    </span>
                </td>
                <td><strong>${item.severity}</strong></td>
            `;
      tbody.appendChild(row);
    });
  } catch (err) {
    tbody.innerHTML =
      '<tr><td colspan="6">Error parsing intelligence telemetry.</td></tr>';
  }
}

fetchSecurityData();
