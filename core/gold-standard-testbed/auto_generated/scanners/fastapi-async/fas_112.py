# Vulnerable: FAS-112
@register.filter(is_safe=True)
def apnumber(value):
    """
    For numbers 1-9, return the number spelled out. Otherwise, return the
    number. This follows Associated Press style.
    """
    try:
        value = int(value)
    except (TypeError, ValueError):
        return value
...
# Perform the comparison in the default time zone when USE_TZ = True
# (unless a specific time zone has been applied with the |timezone filter).
