from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.collectors.cis import CisBenchmarkCollector
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.clients.wazuh_manager import WazuhManagerClient
from src.collectors.vulnerability import VulnerabilityCollector
from src.collectors.log import LogCollector
from src.collectors.fim import FimCollector
from src.collectors.malware import MalwareCollector
from src.collectors.compliance import ComplianceCollector

class KPIService:
    def __init__(
        self,
        indexer_client: WazuhIndexerClient,
        manager_client: WazuhManagerClient,
    ):
        self._vuln_collector = VulnerabilityCollector(indexer_client)
        self._log_collector = LogCollector(indexer_client, manager_client)
        self._cis_collector = CisBenchmarkCollector(indexer_client)
        self._fim_collector = FimCollector(indexer_client)
        self._malware_collector = MalwareCollector(indexer_client)
        self._compliance_collector = ComplianceCollector(indexer_client)

    def compute_vulnerability_kpis(self, date_from: datetime, date_to: datetime) -> dict:
        vuln = self._vuln_collector
        kpis = {
            "raw_event_count": vuln.get_raw_event_count(date_from, date_to),
            "active_vulns": vuln.get_active_vulnerability_count(date_from, date_to),
            "unique_cve_count": vuln.get_unique_cve_count(date_from, date_to),
            "severity_breakdown": vuln.get_severity_breakdown(date_from, date_to),
            "top10_vulnerable_machines": vuln.get_top10_vulnerable_machines(date_from, date_to),
            "top10_cve": vuln.get_top10_cve(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_log_kpis(self, date_from: datetime, date_to: datetime) -> dict:
        log = self._log_collector
        kpis = {
            "agent_summary": log.get_agent_summary(),
            "never_connected_agents": log.get_never_connected_agents(),
            "confirmed_incidents": log.get_confirmed_incidents(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_cis_kpis(self, date_from: datetime, date_to: datetime) -> dict:
        cis = self._cis_collector
        kpis = {
            "score_global": cis.get_score_global(date_from, date_to),
            "score_by_policy": cis.get_score_by_policy(date_from, date_to),
            "scanned_agent": cis.agents_scanned(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_fim_kpis(
        self,
        date_from: datetime,
        date_to: datetime,
        soc_vp: int = 0,   
        soc_fp: int = 0,
    ) -> dict:
        fim = self._fim_collector
        kpis = {
            "total_fim_events":     fim.get_total_event_count(date_from, date_to),
            "event_type_breakdown": fim.get_event_type_breakdown(date_from, date_to),
            "alert_level_breakdown":fim.get_alert_levels_breakdown(date_from, date_to),
            "mode_coverage":        fim.get_mode_coverage(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_malware_kpis(self, date_from: datetime, date_to: datetime) -> dict:
        malware = self._malware_collector
        kpis = {
            "get_raw_event_count": malware.get_raw_event_count(date_from, date_to),
            "get_real_threat_count": malware.get_real_threat_count(date_from, date_to),
            "get_unique_agents": malware.get_unique_agents(date_from, date_to),
            "get_top10_agents": malware.get_top10_agents(date_from, date_to),
            "get_top10_threats": malware.get_top10_threats(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}
    
    def compute_compliance_kpis(self, date_from: datetime, date_to:datetime) -> dict:
        compliance = self._compliance_collector
        kpis = {
            "get_hippa": compliance.hippa(date_from, date_to),
            "get_rgpd": compliance.rgpd(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_compliance_kpis(self, date_from: datetime, date_to:datetime) -> dict:
        compliance = self._compliance_collector
        kpis = {
            "get_hipaa": compliance.hipaa(date_from, date_to),
            "get_rgpd": compliance.rgpd(date_from, date_to),
        }
        return {key: kpi.model_dump() for key, kpi in kpis.items()}

    def compute_all_kpis(self, date_from: datetime, date_to: datetime) -> dict:
        tasks = {
            "vulnerabilities": self.compute_vulnerability_kpis,
            "logs": self.compute_log_kpis,
            "cis": self.compute_cis_kpis,
            "fim": self.compute_fim_kpis,
            "malware": self.compute_malware_kpis,
	        "compliance": self.compute_compliance_kpis,
        }

        results = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(fn, date_from, date_to): domain
                for domain, fn in tasks.items()
            }
            for future in as_completed(futures):
                domain = futures[future]
                results[domain] = future.result()

        return results
