"""Fetch resources from a real Azure subscription with Azure Resource Graph.

Needs the optional dependencies: pip install "azposture[live]"
and an identity that DefaultAzureCredential can find (az login, a managed identity,
or the AZURE_* environment variables). Reader access on the subscription is enough.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import Resource
from .rules import supported_types

PAGE_SIZE = 1000


def build_query() -> str:
    types = ", ".join(f"'{t}'" for t in sorted(supported_types()))
    return f"Resources | where type in~ ({types}) | project id, name, type, location, properties"


def _azure_request(  # pragma: no cover - needs the azure extras
    subscriptions: list[str], query: str, skip_token: str | None
) -> Any:
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    return QueryRequest(
        subscriptions=subscriptions,
        query=query,
        options=QueryRequestOptions(top=PAGE_SIZE, skip_token=skip_token),
    )


def _azure_client() -> Any:  # pragma: no cover - needs real Azure credentials
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
    except ImportError as exc:
        raise RuntimeError('live mode needs extra packages: pip install "azposture[live]"') from exc
    return ResourceGraphClient(DefaultAzureCredential())


def fetch_resources(
    subscription_ids: list[str],
    client: Any = None,
    make_request: Callable[[list[str], str, str | None], Any] = _azure_request,
) -> list[Resource]:
    """Return all supported resources in the given subscriptions, following pagination.

    ``client`` and ``make_request`` can be replaced in tests, so no Azure account is needed.
    """
    client = client or _azure_client()
    query = build_query()
    resources: list[Resource] = []
    skip_token = None
    while True:
        response = client.resources(make_request(subscription_ids, query, skip_token))
        resources.extend(Resource.from_dict(row) for row in response.data)
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            return resources
