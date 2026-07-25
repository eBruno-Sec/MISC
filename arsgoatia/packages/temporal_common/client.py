"""Temporal client helper. Single place that reads the address/namespace."""

from __future__ import annotations

from config.settings import get_settings


async def get_temporal_client():
    from temporalio.client import Client

    settings = get_settings()
    return await Client.connect(settings.temporal_address, namespace=settings.temporal_namespace)
