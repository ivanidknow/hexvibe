# Vulnerable: FAS-109
active_findings = (
    Finding.objects.filter(
        verified=True,
        active=True,
        severity__in=("Critical", "High", "Medium", "Low", "Info"),
    )
    .prefetch_related(
        "test__engagement__product",
        "test__engagement__product__prod_type",
        "test__engagement__risk_acceptance",
...
)
example = 1
