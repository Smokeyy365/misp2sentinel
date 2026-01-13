#!/usr/bin/env python3
"""
Revoke Indicator Script for Microsoft Sentinel STIX Objects API

This script allows you to revoke indicators in Microsoft Sentinel by:
1. Searching for indicators by name or STIX ID
2. Marking them as revoked
3. Uploading the updated indicator back to Sentinel

Usage:
    python revoke_indicator.py
    
Requirements:
    - config.py with Microsoft Sentinel credentials
    - requests library
"""

import sys
import json
import argparse
from datetime import datetime, timezone
import requests

try:
    import config
except ImportError:
    print("ERROR: config.py not found. Please copy config.py.default to config.py and configure it.")
    sys.exit(1)


def get_access_token():
    """
    Obtain an Azure AD access token for the Sentinel API.
    
    Returns:
        str: Access token
    """
    token_url = f"https://login.microsoftonline.com/{config.ms_auth['tenant_id']}/oauth2/v2.0/token"
    
    token_data = {
        'client_id': config.ms_auth['client_id'],
        'client_secret': config.ms_auth['client_secret'],
        'scope': config.ms_auth['scope'],
        'grant_type': 'client_credentials'
    }
    
    try:
        response = requests.post(token_url, data=token_data, timeout=30)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to obtain access token: {e}")
        sys.exit(1)


def query_sentinel_indicators(token, search_term, search_type='name'):
    """
    Query Sentinel for indicators matching the search term.
    
    Note: The STIX Objects API doesn't provide a built-in query endpoint,
    so this function returns a placeholder. In practice, you would need to:
    1. Use Azure Monitor/Log Analytics to query ThreatIntelligenceIndicator table
    2. Or maintain a local cache of uploaded indicators
    3. Or use the Microsoft Graph Security API (if available)
    
    Args:
        token (str): Access token
        search_term (str): Term to search for
        search_type (str): Type of search - 'name' or 'id'
    
    Returns:
        list: List of matching indicators
    """
    print(f"\nSearching for indicators by {search_type}: {search_term}")
    print("Note: The STIX Objects API doesn't provide query functionality.")
    print("You need to provide the complete STIX object to revoke.")
    print("\nAlternatively, you can:")
    print("1. Query the ThreatIntelligenceIndicator table in Log Analytics")
    print("2. Use the Microsoft Graph Security API")
    print("3. Maintain a local record of uploaded indicators")
    
    return []


def create_revoked_indicator(stix_id, pattern, pattern_type="stix", name=None):
    """
    Create a STIX indicator object with revoked=true.
    
    Args:
        stix_id (str): The STIX ID of the indicator (e.g., indicator--uuid)
        pattern (str): The STIX pattern (e.g., "[ipv4-addr:value = '1.2.3.4']")
        pattern_type (str): Pattern type, default "stix"
        name (str): Optional name for the indicator
    
    Returns:
        dict: STIX indicator object with revoked=true
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "revoked": True,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "pattern_version": "2.1",
        "valid_from": now,
        "valid_until": now  # Set to now to expire immediately
    }
    
    if name:
        indicator["name"] = name
    
    return indicator


def upload_revoked_indicator(token, indicator):
    """
    Upload the revoked indicator to Sentinel.
    
    Args:
        token (str): Access token
        indicator (dict): STIX indicator object
    
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{config.sentinel_api_endpoint}/{config.sentinel_workspace_id}/threatintelligence/stixobjects:upload?api-version=2024-02-01"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    request_body = {
        "sourcesystem": getattr(config, 'sourcesystem', 'MISP'),
        "stixobjects": [indicator]
    }
    
    try:
        if hasattr(config, 'verbose_log') and config.verbose_log:
            print(f"\nUploading to: {url}")
            print(f"Request body:\n{json.dumps(request_body, indent=2)}")
        
        response = requests.post(url, headers=headers, json=request_body, timeout=30)
        
        if response.status_code == 200:
            print(f"\n✓ Successfully revoked indicator: {indicator['id']}")
            return True
        else:
            print(f"\n✗ Failed to revoke indicator: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"\n✗ Error uploading indicator: {e}")
        return False


def interactive_mode(token):
    """
    Interactive CLI mode for revoking indicators.
    
    Args:
        token (str): Access token
    """
    print("\n" + "="*60)
    print("  Microsoft Sentinel Indicator Revocation Tool")
    print("="*60)
    
    while True:
        print("\nOptions:")
        print("1. Revoke indicator by STIX ID and pattern")
        print("2. Exit")
        
        choice = input("\nEnter your choice (1-2): ").strip()
        
        if choice == '2':
            print("\nExiting...")
            break
        elif choice == '1':
            print("\n" + "-"*60)
            print("To revoke an indicator, you need:")
            print("  - STIX ID (e.g., indicator--12345678-1234-1234-1234-123456789abc)")
            print("  - STIX Pattern (e.g., [ipv4-addr:value = '1.2.3.4'])")
            print("-"*60)
            
            stix_id = input("\nEnter STIX ID: ").strip()
            if not stix_id:
                print("ERROR: STIX ID cannot be empty")
                continue
            
            if not stix_id.startswith("indicator--"):
                print("WARNING: STIX ID should start with 'indicator--'")
                confirm = input("Continue anyway? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            
            pattern = input("Enter STIX Pattern: ").strip()
            if not pattern:
                print("ERROR: Pattern cannot be empty")
                continue
            
            name = input("Enter indicator name (optional, press Enter to skip): ").strip()
            pattern_type = input("Enter pattern type (default: stix, press Enter to use default): ").strip() or "stix"
            
            # Create the revoked indicator
            indicator = create_revoked_indicator(stix_id, pattern, pattern_type, name if name else None)
            
            # Show preview
            print("\n" + "-"*60)
            print("Preview of indicator to be revoked:")
            print(json.dumps(indicator, indent=2))
            print("-"*60)
            
            confirm = input("\nConfirm revocation? (y/n): ").strip().lower()
            if confirm == 'y':
                upload_revoked_indicator(token, indicator)
            else:
                print("Revocation cancelled.")
        else:
            print("Invalid choice. Please enter 1 or 2.")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Revoke indicators in Microsoft Sentinel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python revoke_indicator.py
  
  # Revoke specific indicator
  python revoke_indicator.py --id "indicator--abc123" --pattern "[ipv4-addr:value = '1.2.3.4']"
  
  # Revoke with name
  python revoke_indicator.py --id "indicator--abc123" --pattern "[ipv4-addr:value = '1.2.3.4']" --name "Malicious IP"
        """
    )
    
    parser.add_argument('--id', dest='stix_id', help='STIX ID of the indicator to revoke')
    parser.add_argument('--pattern', help='STIX pattern of the indicator')
    parser.add_argument('--name', help='Name of the indicator (optional)')
    parser.add_argument('--pattern-type', default='stix', help='Pattern type (default: stix)')
    
    args = parser.parse_args()
    
    # Get access token
    print("Authenticating with Microsoft Sentinel...")
    token = get_access_token()
    print("✓ Authentication successful")
    
    # Check if command-line arguments were provided
    if args.stix_id and args.pattern:
        # Non-interactive mode
        indicator = create_revoked_indicator(
            args.stix_id,
            args.pattern,
            args.pattern_type,
            args.name
        )
        
        print("\nIndicator to be revoked:")
        print(json.dumps(indicator, indent=2))
        
        if upload_revoked_indicator(token, indicator):
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        # Interactive mode
        if args.stix_id or args.pattern:
            print("ERROR: Both --id and --pattern are required for non-interactive mode")
            print("Run without arguments for interactive mode, or use --help for usage")
            sys.exit(1)
        
        interactive_mode(token)


if __name__ == "__main__":
    main()
