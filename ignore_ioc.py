#!/usr/bin/env python3
"""Interactive helper to find and revoke (ignore) Sentinel TI indicators.

Notes from Microsoft docs:
- Query endpoint: POST .../threatIntelligence/main/queryIndicators?api-version=2025-06-01
- Request body supports `keywords` for searching indicators.
- Pagination uses `nextLink` and request-body `skipToken`.
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests
from tqdm import tqdm

from config import ms_auth, ms_useragent, sentinel_api_endpoint
from functions import _get_access_token, confirm_action, createChoices
from script import logger


QUERY_API_VERSION = "2025-06-01"
UPLOAD_API_VERSION = "2024-02-01-preview"


def ti_getindicator(indicator_name: str) -> Dict[str, Any]:
    """Retrieve details of a specific indicator from Microsoft Sentinel."""
    url = (
        f"https://management.azure.com/subscriptions/{ms_auth['subscription_id']}"
        f"/resourceGroups/{ms_auth['rg_name']}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ms_auth['workspace_name']}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators/{indicator_name}"
        f"?api-version={QUERY_API_VERSION}"
    )

    headers = {
        "Authorization": f"Bearer {_get_access_token()}",
        "user-agent": ms_useragent,
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_message = (
            "Error getting indicator:\n"
            f"Status Code: {getattr(e.response, 'status_code', 'N/A')}\n"
            f"Error: {str(e)}"
        )
        logger.error(error_message)
        return {}


def check_for_hit(indicators: List[Dict[str, Any]], search_term_lower: str):
    """Check candidate indicators and ask the user for confirmation."""
    filtered: List[Dict[str, Any]] = []
    seen = set()
    check_later: List[Dict[str, Any]] = []

    for ind in indicators:
        display_name = ind.get("properties", {}).get("displayName", "")
        value = ind.get("properties", {}).get("pattern", "")
        unique_key = ind.get("name")

        if not unique_key or unique_key in seen:
            continue

        if (search_term_lower in display_name.lower()) or (
            search_term_lower in value.lower()
        ):
            print("\nPotential match found:")
            print(f"Display Name: {display_name}")
            print(f"Pattern: {value}")
            user_input = confirm_action("Is this the correct Indicator?")

            if user_input is True:
                filtered.append(ind)
                return filtered, None

            if user_input is False:
                check_later.append(ind)
                seen.add(unique_key)

    return filtered, check_later


def extract_skip_token(next_link: Optional[str]) -> Optional[str]:
    """Extract skip token from nextLink exactly as provided by Microsoft."""
    if not next_link:
        return None

    query = parse_qs(urlparse(next_link).query)
    token = (query.get("$skipToken") or query.get("skipToken") or [None])[0]
    return token


def iter_ti_pages_follow_nextlink(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout: int = 30,
) -> Generator[List[Dict[str, Any]], None, None]:
    """Page through queryIndicators results.

    Microsoft returns `nextLink`; the same API also supports request-body `skipToken`.
    This iterator keeps POSTing to queryIndicators with skipToken from nextLink,
    which is the documented query body field.
    """
    body = dict(payload)
    next_link: Optional[str] = None

    while True:
        if next_link:
            skip_token = extract_skip_token(next_link)
            if not skip_token:
                raise RuntimeError("Received nextLink without a usable skipToken.")
            body["skipToken"] = skip_token

        response = session.post(url, headers=headers, json=body, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        yield data.get("value", [])

        next_link = data.get("nextLink")
        if not next_link:
            break


def ti_filter_indicators(search_term: str):
    """Filter indicators based on display name or pattern value.

    Uses Microsoft-supported `keywords` for server-side narrowing,
    then performs exact client-side checks for displayName and pattern.
    """
    page_size = 200
    url = (
        f"https://management.azure.com/subscriptions/{ms_auth['subscription_id']}"
        f"/resourceGroups/{ms_auth['rg_name']}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ms_auth['workspace_name']}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version={QUERY_API_VERSION}"
    )

    headers = {
        "Authorization": f"Bearer {_get_access_token()}",
        "user-agent": ms_useragent,
        "Content-Type": "application/json",
    }

    search_term_lower = search_term.lower()
    payload: Dict[str, Any] = {
        "pageSize": page_size,
        "includeDisabled": True,
        "keywords": [search_term],
        "sortBy": [{"itemKey": "lastUpdatedTimeUtc", "sortOrder": "descending"}],
    }

    second_chance_hits: List[Dict[str, Any]] = []
    total_items = 0

    with requests.Session() as session:
        pbar = tqdm(desc="Filtering pages", unit="page")
        for page_items in iter_ti_pages_follow_nextlink(
            session=session,
            url=url,
            headers=headers,
            payload=payload,
            timeout=30,
        ):
            total_items += len(page_items)
            pbar.set_postfix(items=total_items)
            pbar.update(1)

            got_a_hit, check_later = check_for_hit(page_items, search_term_lower)
            if got_a_hit:
                pbar.close()
                return True, got_a_hit

            if check_later:
                second_chance_hits.extend(check_later)

        pbar.close()

    if second_chance_hits:
        got_a_hit, _ = check_for_hit(second_chance_hits, search_term_lower)
        if got_a_hit:
            return True, got_a_hit

    return False, f"Nothing was found for {search_term}. Try again."


def ignore_indicator(indicator: Dict[str, Any]) -> Tuple[bool, str]:
    """Revoke an indicator so it is ignored by Sentinel detections."""
    url = (
        f"{sentinel_api_endpoint}/workspaces/{ms_auth['workspace_id']}"
        f"/threat-intelligence-stix-objects:upload?api-version={UPLOAD_API_VERSION}"
    )

    headers = {
        "Authorization": f"Bearer {_get_access_token()}",
        "Content-Type": "application/json",
        "user-agent": ms_useragent,
    }

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

    properties = indicator.get("properties", {})
    stix_indicator = {
        "type": "indicator",
        "confidence": properties.get("confidence"),
        "created_by_ref": properties.get("createdByRef"),
        "kill_chain_phases": properties.get("killChainPhases"),
        "name": properties.get("displayName"),
        "extensions": properties.get("extensions"),
        "id": properties.get("externalId"),
        "created": properties.get("created"),
        "modified": now,
        "revoked": True,
        "pattern": properties.get("pattern"),
        "pattern_type": properties.get("patternType"),
        "pattern_version": "2.1",
        "valid_from": properties.get("validFrom"),
        "valid_until": properties.get("validUntil"),
        "labels": properties.get("labels"),
    }

    request_body = {"sourcesystem": "MISP", "stixobjects": [stix_indicator]}

    try:
        response = requests.post(url, headers=headers, json=request_body, timeout=30)
        response.raise_for_status()
        print(f"Successfully revoked indicator: {stix_indicator.get('id')}")
        return True, "Ignore action successful"
    except requests.exceptions.RequestException as e:
        error_message = (
            "Error updating indicator:\n"
            f"Status Code: {getattr(e.response, 'status_code', 'N/A')}\n"
            f"Error: {str(e)}"
        )
        return False, error_message


def menu_remove_ioc():
    """Ignore indicator by known Azure indicator name."""
    print("\n--- IGNORE AN IOC ---")
    chosen_ioc = input("\nEnter name (ID) for the IOC: ")
    ioc = ti_getindicator(chosen_ioc)

    print("\nCurrent Details\n---------------")
    print(json.dumps(ioc, indent=4))

    if not ioc:
        return

    answer = confirm_action("Is this the correct Indicator?")
    if answer is False:
        return menu_remove_ioc()

    answer = confirm_action("Are you sure you want to ignore this IoC?")
    if answer is False:
        return

    _, message = ignore_indicator(ioc)
    print(message)


def menu_find_ioc():
    """Search IOC by name/pattern, then ignore it."""
    print("\n--- FIND AN IOC ---")
    search_term = input("\nEnter the name/value of the IOC: ")
    _, res = ti_filter_indicators(search_term)

    if isinstance(res, str):
        print("Error: " + res)
        return

    answer = confirm_action("Are you sure you want to ignore this IoC?")
    if answer is True:
        ignore_indicator(res[0])


def main_menu():
    """Display the main menu and process user input."""
    while True:
        print("\n=== MISP->SentinelOne ============")
        print("=== IGNORE IoC SCRIPT ===")
        print("==================================")

        choice = createChoices("", ["Ignore an IOC", "Exit Script"])

        match choice:
            case "Ignore an IOC":
                choice = createChoices(
                    "Choose an IOC", ["Search for IOC", "I have the name (hash)"]
                )
                match choice:
                    case "Search for IOC":
                        menu_find_ioc()
                    case "I have the name (hash)":
                        menu_remove_ioc()
                    case _:
                        print("Invalid selection. Please try again.")
            case "Exit Script":
                print("Exiting program.")
                break
            case _:
                print("Invalid selection. Please try again.")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nExiting Program...\n")
        sys.exit(0)
