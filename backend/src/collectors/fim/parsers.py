class FimParsers:

    @staticmethod
    def total_event_count(response: dict) -> dict:
        raw    = response.get("hits", {}).get("total", {}).get("value", 0)
        unique = response.get("aggregations", {}).get("unique_events", {}).get("value", 0)
        return {
            "value":         unique,
            "raw_documents": raw,
        }

    @staticmethod
    def buckets(response: dict, agg_name: str) -> list:
        return response.get("aggregations", {}).get(agg_name, {}).get("buckets", [])

    @staticmethod
    def cardinality(response: dict, agg_name: str) -> int:
        return response.get("aggregations", {}).get(agg_name, {}).get("value", 0)

    @staticmethod
    def filter_count(response: dict, agg_name: str) -> int:
        return response.get("aggregations", {}).get(agg_name, {}).get("doc_count", 0)

    @classmethod
    def event_type_breakdown(cls, response: dict) -> dict:
        aggs = response.get("aggregations", {})

        added_unique    = aggs.get("added",   {}).get("unique", {}).get("value", 0)
        deleted_unique  = aggs.get("deleted", {}).get("unique", {}).get("value", 0)

        mod_agg         = aggs.get("modified", {})
        modified_unique = mod_agg.get("unique",    {}).get("value", 0)
        hash_unique     = mod_agg.get("avec_hash", {}).get("unique", {}).get("value", 0)
        mtime_only      = max(0, modified_unique - hash_unique)

        return {
            "added":          added_unique,
            "modified_total": modified_unique,
            "modified_hash":  hash_unique,
            "modified_mtime": mtime_only,
            "deleted":        deleted_unique,
        }

    @classmethod
    def alert_levels_breakdown(cls, response: dict) -> dict:
        aggs = response.get("aggregations", {})
        return {
            "critical": aggs.get("critical", {}).get("doc_count", 0),
            "high":     aggs.get("high",     {}).get("doc_count", 0),
        }

    @classmethod
    def mode_coverage(cls, response: dict) -> dict:
        buckets = cls.buckets(response, "par_mode")
        counts  = {b["key"]: b["doc_count"] for b in buckets}
        total   = sum(counts.values()) or 1
        return {
            "realtime":      counts.get("realtime",  0),
            "scheduled":     counts.get("scheduled", 0),
            "whodata":       counts.get("whodata",   0),
            "realtime_pct":  round(counts.get("realtime",  0) / total * 100, 2),
            "scheduled_pct": round(counts.get("scheduled", 0) / total * 100, 2),
            "whodata_pct":   round(counts.get("whodata",   0) / total * 100, 2),
        }
