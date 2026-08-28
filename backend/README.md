# Wazuh Weekly Report

## Description

Wazuh Weekly Report est une solution automatisée permettant de collecter des indicateurs de sécurité depuis Wazuh Manager et Wazuh Indexer, de générer un rapport hebdomadaire au format PDF, puis de l'envoyer automatiquement par e-mail aux parties prenantes (SOC, RSSI, équipes IT, direction).

Le projet vise à fournir une vision consolidée de l'état de la supervision de sécurité et de la conformité ISO 27001 à travers des indicateurs clés de performance (KPI).

---

## Objectifs

* Automatiser la collecte des données Wazuh.
* Centraliser les KPI sécurité hebdomadaires.
* Générer un rapport PDF professionnel.
* Envoyer automatiquement le rapport par e-mail.
* Conserver un historique des métriques pour le suivi des tendances.

---

## Fonctionnalités

### Collecte des données

#### Wazuh Manager API

* Inventaire des agents
* État des agents
* Agents actifs/inactifs
* Agents jamais connectés
* Vulnérabilités détectées
* Informations Syscollector

#### Wazuh Indexer API

* Volume de logs
* Alertes de sécurité
* Agrégations statistiques
* Top règles déclenchées
* Top agents générateurs d'événements

---

## KPI suivis

### Couverture de supervision

* Nombre total d'agents
* Nombre d'agents actifs
* Nombre d'agents inactifs
* Nombre d'agents jamais connectés
* Taux de couverture des agents

### Couverture des logs

* Nombre d'agents ayant envoyé des logs
* Nombre total d'événements
* Taux de couverture des logs

### Vulnérabilités

* Vulnérabilités critiques
* Vulnérabilités élevées
* Vulnérabilités moyennes
* Vulnérabilités faibles

### Détection

* Nombre total d'alertes
* Alertes critiques
* Top règles déclenchées
* Top agents générateurs d'événements

---

## Architecture

```text
Wazuh Manager
       │
       ├── Agents
       ├── Vulnerabilities
       └── Inventory
               │
               ▼
        Collectors
               │
               ▼
         KPI Service
               │
               ▼
        Report Service
               │
               ▼
        PDF Generator
               │
               ▼
         SMTP Service
               │
               ▼
          Recipients
```

---

## Structure du projet

```text
wazuh-weekly-report/
│
├── config/
├── clients/
├── collectors/
├── services/
├── templates/
├── reports/
├── utils/
├── scheduler/
├── tests/
│
├── main.py
└── requirements.txt
```

---

## Technologies

### Backend

* Python 3.12+
* Requests
* OpenSearch Python Client

### Reporting

* Jinja2
* WeasyPrint

### Notifications

* SMTP
* Email MIME

### Planification

* Cron (Linux)
* Task Scheduler (Windows)

---

## Cycle d'exécution

1. Authentification auprès du Wazuh Manager.
2. Collecte des données du Manager.
3. Collecte des données de l'Indexer.
4. Calcul des KPI.
5. Génération du rapport HTML.
6. Conversion du rapport en PDF.
7. Envoi du rapport par e-mail.
8. Archivage du rapport généré.

---

## Exemple de rapport

Le rapport hebdomadaire contient :

### Résumé exécutif

* État global de la plateforme
* Principales observations
* Risques identifiés

### Indicateurs clés

| KPI                      | Valeur |
| ------------------------ | ------ |
| Agents enregistrés       | XXX    |
| Agents actifs            | XXX    |
| Couverture agents        | XX %   |
| Événements reçus         | XXX    |
| Couverture logs          | XX %   |
| Vulnérabilités critiques | XXX    |

### Analyses

* Top agents générateurs d'événements
* Top règles déclenchées
* Répartition des vulnérabilités
* Tendances hebdomadaires

---

## Configuration

Le fichier `config/config.yaml` contient :

* Paramètres Wazuh Manager
* Paramètres Wazuh Indexer
* Paramètres SMTP
* Destinataires du rapport

---

## Exécution manuelle

```bash
python main.py
```

---

## Exécution automatique

### Linux

```bash
0 7 * * 1 python3 /opt/wazuh-weekly-report/main.py
```

### Windows

Créer une tâche planifiée exécutant :

```powershell
python C:\wazuh-weekly-report\main.py
```

chaque lundi matin.

---

## Évolutions futures

* Tableau de bord web.
* Historisation en base SQLite/PostgreSQL.
* Génération de graphiques de tendances.
* Export Excel.
* Multi-environnements (DEV, RECETTE, PROD).
* Intégration Microsoft Teams.
* Intégration Slack.
* Génération de rapports mensuels et trimestriels.
* Mapping automatique ISO 27001 et CIS Controls.

---

## Cas d'usage

Cette solution est adaptée pour :

* Centre opérationnel de sécurité (SOC)
* Équipes cybersécurité
* RSSI
* Audits ISO 27001
* Reporting de conformité
* Suivi des vulnérabilités
* Pilotage de la couverture de supervision
