/* Connects the supplied Social Sync dashboard to the Flask API.
   The existing visual layout remains untouched. */
(function () {
  const $ = (id) => document.getElementById(id);
  const label = (id, value) => { const element = $(id); if (element) element.textContent = value; };
  const escapeHtml = (value) => String(value || '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
  const trafficValue = (value) => Number(String(value).replace(/[+,]/g, '').replace(/K$/i, '000').replace(/M$/i, '000000')) || 0;

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
            <p class="text-sm font-bold text-white">${escapeHtml(record.cve || 'Threat signal')}</p>
            <span class="text-[10px] text-slate-500">${escapeHtml(record.source || record.vendor || 'Public feed')}</span>
            <span class="ml-auto text-[10px] font-bold text-rose-300">${escapeHtml(record.threat_status || record.severity || 'PUBLIC')}</span>
          </div>
          <p class="mt-1 text-xs leading-5 text-slate-500">${escapeHtml(record.name || record.required_action || 'No details available')}</p>
        </div>
      </div>`).join('');
  }

  async function refreshFromBackend() {
    const params = filters();
    try {
      const [summaryResponse, feedResponse, trendsResponse] = await Promise.all([
        fetch(`/api/threats/summary?${params}`),
        fetch(`/api/threats/feed?${params}`),
        fetch('/api/trends?geo=IN')
      ]);
      if (!summaryResponse.ok || !feedResponse.ok || !trendsResponse.ok) throw new Error('API unavailable');
      const summary = await summaryResponse.json();
      const feed = await feedResponse.json();
      const trends = await trendsResponse.json();
      label('overallThreats', Number(summary.overall_threats).toLocaleString());
      label('criticalThreats', Number(summary.critical_threats).toLocaleString());
      label('coordinatedThreats', summary.coordinated_clusters);
      label('liveStatus', `Public intelligence · ${summary.severity.toUpperCase()} priority`);
      formatFeed(feed.records);
      const top = feed.records?.[0];
      if (top) {
        label('aiPredictedThreat', top.cve);
        label('aiPredictionProbability', top.epss_probability == null ? 'Known exploited' : `${(top.epss_probability * 100).toFixed(1)}%`);
        label('aiPredictionWindow', feed.analysis?.forecast_window || 'next 30 days');
        label('aiPredictionReason', feed.analysis?.forecast || 'Public intelligence analysis unavailable.');
      }
      const insightBox = $('quickInsights');
      if (insightBox && trends.items?.length) {
        insightBox.innerHTML = trends.items.slice(0, 4).map((trend) => `<div class="rounded-xl border border-white/10 bg-white/[.035] p-3"><p class="text-sm font-bold text-white">${escapeHtml(trend.topic)}</p><p class="mt-1 text-xs text-slate-400">${escapeHtml(trend.traffic || 'Trending')} · Google Trends India</p></div>`).join('');
      }
      const trendBars = $('categoryBars');
      if (trendBars && trends.items?.length) {
        const maxTraffic = Math.max(...trends.items.map((trend) => trafficValue(trend.traffic)), 1);
        trendBars.innerHTML = trends.items.slice(0, 5).map((trend) => `<div><div class="mb-1 flex justify-between gap-3 text-xs"><span class="truncate text-slate-300">${escapeHtml(trend.topic)}</span><span class="shrink-0 text-slate-500">${escapeHtml(trend.traffic || '—')}</span></div><div class="h-2 overflow-hidden rounded-full bg-white/5"><div class="h-full rounded-full bg-gradient-to-r from-cyan-400 to-indigo-400" style="width:${Math.max(4, (trafficValue(trend.traffic) / maxTraffic) * 100)}%"></div></div></div>`).join('');
      }
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
