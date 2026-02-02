// Simple client-side filters for the results table
window.addEventListener('DOMContentLoaded', () => {
  const scoreInput = document.getElementById('filterScore');
  const statusSelect = document.getElementById('filterStatus');
  const table = document.getElementById('scanTable');
  if (!scoreInput || !statusSelect || !table) return;
  function applyFilters() {
    const minScore = parseInt(scoreInput.value || '0', 10);
    const status = statusSelect.value;
    for (const tr of table.querySelectorAll('tr')) {
      const tds = tr.querySelectorAll('td');
      if (tds.length < 5) continue;
      const score = parseInt(tds[2].innerText.trim(), 10);
      const st = tds[3].innerText.trim();
      const okScore = isNaN(minScore) ? true : score >= minScore;
      const okStatus = !status || st === status;
      tr.style.display = okScore && okStatus ? '' : 'none';
    }
  }
  scoreInput.addEventListener('input', applyFilters);
  statusSelect.addEventListener('change', applyFilters);
});

