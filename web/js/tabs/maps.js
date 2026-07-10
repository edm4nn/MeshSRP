// Shell placeholder: GPS_BROADCAST e vista mappa/radar arrivano insieme
// alla pipeline messaggi.

export function mount(container) {
  container.innerHTML = `
    <div class="placeholder">
      <div class="placeholder-title">Mappe</div>
      <p>Le posizioni squadra (GPS_BROADCAST, vista radar offline)
      arrivano nella prossima milestone.</p>
      <span class="placeholder-badge">IN ARRIVO</span>
    </div>
  `;
}
