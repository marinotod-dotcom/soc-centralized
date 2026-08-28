import os
from dotenv import load_dotenv

load_dotenv()
REFERENCE_FLEET = int(os.getenv("REFERENCE_FLEET", "926"))


class LogParsers:

    @staticmethod
    def total_hits(response: dict) -> int:
        return response.get("hits", {}).get("total", {}).get("value", 0)

    @classmethod
    def agent_summary(cls, response: dict) -> dict:
        data = response.get("data", {})
        status = data.get("status", {})
        groups = data.get("groups", {})
        never_connected = status.get("never_connected", 0)
        total_declared = groups.get("default", 0)

        coverage_rate = (
            round(total_declared / REFERENCE_FLEET * 100, 2) if REFERENCE_FLEET else 0.0
        )

        return {
            "total_declared": total_declared,
            "never_connected": never_connected,
            "coverage_rate_pct": coverage_rate,
            "compliant": coverage_rate >= 99.0,
        }

    @staticmethod
    def never_connected_agents(response: dict, total_declared: int) -> dict:
        data = response.get("data", {})
        never_connected = data.get("total_affected_items", 0)
        active = total_declared - never_connected
        coverage_logs_percentage = (
            round(active / REFERENCE_FLEET * 100, 2) if REFERENCE_FLEET else 0.0
        )

        return {
            "never_connected": never_connected,
            "coverage_logs_percentage": coverage_logs_percentage,
        }

    @classmethod
    def confirmed_incidents(cls, response: dict) -> dict:
        total = response.get("hits", {})
        aggs = response.get("aggregations", {})

        return {
            "count_total": total.get("total", {}).get("value", 0),
            "count": aggs.get("total_uniques", {}).get("value", 0),
        }
