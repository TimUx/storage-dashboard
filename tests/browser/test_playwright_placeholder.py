"""Optional: echtes Browser-E2E mit Playwright (nicht Teil der Standard-CI).

Installation::

    pip install pytest-playwright
    playwright install chromium

Ausführung::

    pytest tests/browser -m browser_e2e
"""
import os

import pytest


@pytest.mark.browser_e2e
@pytest.mark.skipif(
    not os.environ.get('PLAYWRIGHT_E2E'),
    reason='Set PLAYWRIGHT_E2E=1 and install pytest-playwright to run browser tests.',
)
def test_placeholder_browser_not_run_by_default():
    """Reservierter Platz für zukünftige Playwright-Szenarien."""
    raise AssertionError('Implement Playwright flows when PLAYWRIGHT_E2E=1')
