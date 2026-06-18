# Vulnerable: NOV-CWE-532
logger = logging.getLogger(__name__)
def debug_credentials(user, password):
logger.debug(f'User: {user}, Pass: {password}')
