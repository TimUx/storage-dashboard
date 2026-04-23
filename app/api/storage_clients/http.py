"""HTTP session used for all calls to local storage systems.

Empty proxy strings override HTTP_PROXY / HTTPS_PROXY so internal storage
is never routed through an internet proxy.
"""
import warnings

import requests

_local_session = requests.Session()
_local_session.proxies.update({"http": "", "https": ""})

MAX_RESPONSE_LOG_LENGTH = 500

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
