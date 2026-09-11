/* Connects the supplied Social Sync dashboard to the Flask API.
   The existing visual layout remains untouched. */
(function () {
  const $ = (id) => document.getElementById(id);
  const label = (id, value) => { const element = $(id); if (element) element.textContent = value; };

  function filters() {
    return new URLSearchParams({
      app: $('threatApp')?.value || 'all',
      category: $('threatCategory')?.value || 'all',
      audience: $('threatAudience')?.value || 'all'
    });
  }

  function formatFeed(records) {
    const feed = $('threatFeed');
    if (!feed || !records?.length) return;
    feed.innerHTML = records.map((record) => `
      <div class="flex gap-3 py-3">
        <span class="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full bg-rose-400"></span>
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <p class="text-sm font-bold text-white">${record.cve || 'Threat signal'}</p>
            <span class="text-[10px] text-slate-500">${record.vendor || 'Public feed'}</span>
            <span class="ml-auto text-[10px] font-bold text-rose-300">KEV</span>
          </div>
          <p class="mt-1 text-xs leading-5 text-slate-500">${record.name || record.required_action || 'No details available'}</p>
        </div>
      </div>`).join('');
  }

  async function refreshFromBackend() {
    const params = filters();
    try {
      const [summaryResponse, feedResponse] = await Promise.all([
        fetch(`/api/threats/summary?${params}`),
        fetch(`/api/threats/feed?${params}`)
      ]);
      if (!summaryResponse.ok || !feedResponse.ok) throw new Error('API unavailable');
      const summary = await summaryResponse.json();
      const feed = await feedResponse.json();
      label('overallThreats', Number(summary.overall_threats).toLocaleString());
      label('criticalThreats', Number(summary.critical_threats).toLocaleString());
      label('coordinatedThreats', summary.coordinated_clusters);
      label('liveStatus', `Backend live · ${summary.severity.toUpperCase()} risk`);
      formatFeed(feed.records);
    } catch (error) {
      label('liveStatus', 'Demo data · backend unavailable');
      console.warn('Social Sync API request failed:', error);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    ['threatApp', 'threatCategory', 'threatAudience'].forEach((id) => {
      $(id)?.addEventListener('change', () => setTimeout(refreshFromBackend, 25));
    });
    refreshFromBackend();
    setInterval(refreshFromBackend, 60000);
  });
})();
