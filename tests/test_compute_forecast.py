"""Tests for compute_forecast in app/capacity_service.py.

Verifies that:
1. Forecast labels are generated at the same step interval as the input data.
2. The number of generated forecast steps is derived from forecast_days // step_days.
3. Forecast values are non-negative and follow the regression trend.
4. Edge cases (empty data, single point, constant values) are handled correctly.
"""

import pytest
from datetime import date, timedelta

from app.capacity_service import compute_forecast


def _make_weekly_labels(start: str, n: int):
    """Return n weekly ISO-date strings starting from start."""
    d = date.fromisoformat(start)
    return [(d + timedelta(weeks=i)).isoformat() for i in range(n)]


def _make_daily_labels(start: str, n: int):
    """Return n daily ISO-date strings starting from start."""
    d = date.fromisoformat(start)
    return [(d + timedelta(days=i)).isoformat() for i in range(n)]


# ── Step detection ────────────────────────────────────────────────────────────

class TestComputeForecastStepDetection:
    """Forecast labels should match the historical data step interval."""

    def test_weekly_data_generates_weekly_forecast(self):
        labels = _make_weekly_labels('2024-01-01', 20)
        values = [float(i) for i in range(20)]
        result = compute_forecast(labels, values, forecast_days=14)
        # With step=7 and forecast_days=14: n_steps = 14 // 7 = 2
        assert len(result['labels']) == 2
        first_fc = date.fromisoformat(result['labels'][0])
        last_hist = date.fromisoformat(labels[-1])
        assert (first_fc - last_hist).days == 7

    def test_daily_data_generates_daily_forecast(self):
        labels = _make_daily_labels('2024-01-01', 20)
        values = [float(i) for i in range(20)]
        result = compute_forecast(labels, values, forecast_days=7)
        # With step=1 and forecast_days=7: n_steps = 7 // 1 = 7
        assert len(result['labels']) == 7
        first_fc = date.fromisoformat(result['labels'][0])
        last_hist = date.fromisoformat(labels[-1])
        assert (first_fc - last_hist).days == 1

    def test_forecast_labels_are_evenly_spaced_weekly(self):
        labels = _make_weekly_labels('2024-01-01', 10)
        values = [float(i) * 2 for i in range(10)]
        result = compute_forecast(labels, values, forecast_days=28)
        # n_steps = 28 // 7 = 4
        assert len(result['labels']) >= 2
        dates = [date.fromisoformat(l) for l in result['labels']]
        gaps = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
        assert all(g == 7 for g in gaps), f"Expected all gaps=7, got {gaps}"


# ── Proportional forecast size ────────────────────────────────────────────────

class TestComputeForecastProportionalSize:
    """Forecast should be proportional to the number of historical data points."""

    def test_forecast_does_not_dominate_chart_for_short_range(self):
        """For ~13 weekly points (3-month range), forecast_days=7 gives 1 weekly point."""
        labels = _make_weekly_labels('2024-10-01', 13)
        values = [10.0 + i * 0.5 for i in range(13)]
        result = compute_forecast(labels, values, forecast_days=7)
        # 7 // 7 = 1 forecast step
        assert len(result['labels']) == 1
        ratio = len(result['labels']) / (len(labels) + len(result['labels']))
        assert ratio < 0.20, f"Forecast takes {ratio:.0%} of chart, expected <20%"

    def test_forecast_does_not_dominate_chart_for_medium_range(self):
        """For ~52 weekly points (1-year range), forecast_days=7 gives 1 weekly point."""
        labels = _make_weekly_labels('2024-01-01', 52)
        values = [20.0 + i * 0.2 for i in range(52)]
        result = compute_forecast(labels, values, forecast_days=7)
        ratio = len(result['labels']) / (len(labels) + len(result['labels']))
        assert ratio < 0.15, f"Forecast takes {ratio:.0%} of chart, expected <15%"


# ── Regression quality ────────────────────────────────────────────────────────

class TestComputeForecastValues:
    """Forecast values should follow the linear trend and be non-negative."""

    def test_forecast_values_non_negative(self):
        labels = _make_weekly_labels('2024-01-01', 10)
        values = [5.0, 4.5, 4.0, 3.5, 3.0, 2.5, 2.0, 1.5, 1.0, 0.5]
        result = compute_forecast(labels, values, forecast_days=21)
        assert all(v >= 0 for v in result['values']), "Forecast values must be non-negative"

    def test_forecast_follows_increasing_trend(self):
        labels = _make_daily_labels('2024-01-01', 10)
        values = [float(i) for i in range(10)]  # clear upward trend
        result = compute_forecast(labels, values, forecast_days=3)
        # Each forecast value should be larger than the last historical value
        assert result['values'][0] > values[-1]

    def test_forecast_follows_decreasing_trend_clamped_at_zero(self):
        labels = _make_daily_labels('2024-01-01', 5)
        values = [10.0, 8.0, 6.0, 4.0, 2.0]
        result = compute_forecast(labels, values, forecast_days=10)
        assert all(v >= 0 for v in result['values'])


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestComputeForecastEdgeCases:
    def test_empty_returns_empty(self):
        result = compute_forecast([], [], forecast_days=7)
        assert result == {'labels': [], 'values': []}

    def test_single_point_returns_empty(self):
        result = compute_forecast(['2024-01-01'], [10.0], forecast_days=7)
        assert result == {'labels': [], 'values': []}

    def test_constant_values_returns_constant_forecast(self):
        labels = _make_daily_labels('2024-01-01', 5)
        values = [50.0] * 5
        result = compute_forecast(labels, values, forecast_days=3)
        assert len(result['values']) == 3
        assert all(abs(v - 50.0) < 0.1 for v in result['values'])

    def test_at_least_one_step_even_when_forecast_days_lt_step(self):
        """When forecast_days < step_days, we should still get at least 1 step."""
        labels = _make_weekly_labels('2024-01-01', 5)
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = compute_forecast(labels, values, forecast_days=3)  # 3 < 7
        assert len(result['labels']) >= 1
        assert len(result['values']) >= 1
