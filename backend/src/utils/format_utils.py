def format_thousands(value):
    if value is None:
        return "-"
    return f"{int(value):,}".replace(",", ".")


def format_fr(value, decimals=2):
    return (
        f"{value:,.{decimals}f}".replace(",", "§").replace(".", ",").replace("§", ".")
    )
