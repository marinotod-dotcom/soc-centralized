export class DailyActionPlanCalendar {
  constructor({ containerId, onDateSelect }) {
    this.container = document.getElementById(containerId);
    this.onDateSelect = onDateSelect;
    this.availableDates = new Set();
    this.selectedDate = null;
    this.viewYear = null;
    this.viewMonth = null;
    this.initialized = false;
  }

  // Appelé uniquement au premier clic sur le bouton "Choisir une date"
  async ensureLoaded() {
    if (this.initialized) return;

    let dates;
    try {
      const res = await fetch('/api/daily-action-plan/dates');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      ({ dates } = await res.json());
    } catch (err) {
      console.error('Impossible de charger les dates disponibles', err);
      this.container.innerHTML = '<p>Erreur de chargement des dates.</p>';
      return;
    }

    this.availableDates = new Set(dates);

    if (dates.length === 0) {
      this.container.innerHTML = '<p>Aucune donnée disponible pour le moment.</p>';
      return;
    }

    const [y, m] = dates[0].split('-').map(Number);
    this.viewYear = y;
    this.viewMonth = m - 1;
    this.initialized = true;

    this._bindNav();
    this._render();
  }

  // Aligne la sélection visuelle sur le jour actuellement affiché (ex: après latest.json),
  // sans déclencher onDateSelect ni refetch.
  setSelectedDate(day) {
    this.selectedDate = day;
    if (this.initialized) this._render();
  }

  _bindNav() {
    document.getElementById('prev-month').addEventListener('click', () => {
      this.viewMonth--;
      if (this.viewMonth < 0) { this.viewMonth = 11; this.viewYear--; }
      this._render();
    });
    document.getElementById('next-month').addEventListener('click', () => {
      this.viewMonth++;
      if (this.viewMonth > 11) { this.viewMonth = 0; this.viewYear++; }
      this._render();
    });
  }

  _render() {
    const monthNames = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre',
    ];
    document.getElementById('current-month-label').textContent =
      `${monthNames[this.viewMonth]} ${this.viewYear}`;

    const grid = document.getElementById('date-picker-grid');
    grid.innerHTML = '';

    const firstDay = new Date(this.viewYear, this.viewMonth, 1);
    const startOffset = (firstDay.getDay() + 6) % 7;
    const daysInMonth = new Date(this.viewYear, this.viewMonth + 1, 0).getDate();

    for (let i = 0; i < startOffset; i++) {
      grid.appendChild(document.createElement('div'));
    }

    for (let day = 1; day <= daysInMonth; day++) {
      const dateStr = `${this.viewYear}-${String(this.viewMonth + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const cell = document.createElement('button');
      cell.type = 'button';
      cell.textContent = day;
      cell.className = 'date-cell';

      if (this.availableDates.has(dateStr)) {
        cell.addEventListener('click', () => this._select(dateStr));
      } else {
        cell.disabled = true;
        cell.classList.add('unavailable');
      }

      if (dateStr === this.selectedDate) {
        cell.classList.add('selected');
      }

      grid.appendChild(cell);
    }
  }

  async _select(dateStr) {
    this.selectedDate = dateStr;
    this._render();
    await this.onDateSelect(dateStr);
  }
}