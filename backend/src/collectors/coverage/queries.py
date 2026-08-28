from datetime import datetime

class CoverageQueries:

    @staticmethod
    def never_connected_agents_url(
        older_than: str = "30d",
        limit: int = 500,
        offset: int = 0,
    ) -> str:
        return (
            "/agents"
            "?status=disconnected"
            f"&older_than={older_than}"
            "&select=id,name,ip,os.platform,dateAdd,lastKeepAlive,group"
            f"&limit={limit}"
            f"&offset={offset}"
        )

    @staticmethod
    def total_agents_url(limit: int = 1, offset: int = 0) -> str:
        return (
            "/agents"
            "?select=id"
            f"&limit={limit}"
            f"&offset={offset}"
        )