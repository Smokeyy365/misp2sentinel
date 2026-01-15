#!/usr/bin/env python3
"""
Revoke Indicator Script for Microsoft Sentinel STIX Objects API

This script allows you to revoke indicators in Microsoft Sentinel by:
1. Querying the indicator from Log Analytics by STIX ID
2. Preserving all original indicator data
3. Updating only the revoked status and valid_until timestamp
4. Uploading the updated indicator back to Sentinel

Usage:
    python revoke_indicator.py --id "indicator--abc123..."
    
Requirements:
    - config.py with Microsoft Sentinel credentials
    - requests library
    - azure-monitor-query library
"""

import sys
import json
import argparse
from datetime import datetime, timezone, timedelta
import requests

try:
    import config
except ImportError:
    print("ERROR: config.py not found. Please copy config.py.default to config.py and configure it.")
    sys.exit(1)

try:
    from azure.monitor.query import LogsQueryClient
    from azure.core.credentials import AccessToken
    from azure.core.exceptions import HttpResponseError
except ImportError:
    print("ERROR: azure-monitor-query library not found.")
    print("Please install it: pip install azure-monitor-query")
    sys.exit(1)


class TokenCredential:
    """Simple credential wrapper for Azure SDK."""
    def __init__(self, token):
        self.token = token
    
    def get_token(self, *scopes, **kwargs):
        """Return the access token."""
        # Tokens typically expire in 1 hour
        expires_on = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        return AccessToken(self.token, expires_on)


def get_access_token(scope=None):
    """
    Obtain an Azure AD access token.
    
    Args:
        scope (str): Optional scope override. If None, uses config.ms_auth['scope']
    
    Returns:
        str: Access token
    """
    token_url = f"https://login.microsoftonline.com/{config.ms_auth['tenant_id']}/oauth2/v2.0/token"
    
    # Use provided scope or default from config
    token_scope = scope if scope else config.ms_auth['scope']
    
    token_data = {
        'client_id': config.ms_auth['client_id'],
        'client_secret': config.ms_auth['client_secret'],
        'scope': token_scope,
        'grant_type': 'client_credentials'
    }
    
    try:
        response = requests.post(token_url, data=token_data, timeout=30)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to obtain access token: {e}")
        sys.exit(1)


def query_indicator_from_sentinel(stix_id):
    """
    Query Sentinel Log Analytics for the indicator details.
    
    Args:
        stix_id (str): The STIX ID of the indicator
    
    Returns:
        dict: The original STIX object, or None if not found
    """
    print(f"\nQuerying Sentinel for indicator: {stix_id}")
    
    # Get Log Analytics access token (different scope than Sentinel API)
    la_token = get_access_token("https://api.loganalytics.io/.default")
    
    # Create Log Analytics client
    credential = TokenCredential(la_token)
    client = LogsQueryClient(credential)
    
    # KQL query to find the indicator
    query = f"""
    ThreatIntelligenceIndicator
    | where TimeGenerated > ago(90d)
    | extend StixObject = parse_json(AdditionalInformation)
    | where tostring(StixObject.id) == "{stix_id}"
    | top 1 by TimeGenerated desc
    | project StixObject
    """
    
    try:
        # Query Log Analytics
        response = client.query_workspace(
            workspace_id=config.sentinel_workspace_id,
            query=query,
            timespan=timedelta(days=90)
        )
        
        # Check if we got results
        if not response.tables or len(response.tables) == 0:
            print(f"ERROR: No indicator found with ID: {stix_id}")
            return None
        
        table = response.tables[0]
        if len(table.rows) == 0:
            print(f"ERROR: No indicator found with ID: {stix_id}")
            return None
        
        # Extract the STIX object from the first row
        stix_object_str = table.rows[0][0]
        stix_object = json.loads(stix_object_str)
        
        print(f"✓ Found indicator: {stix_object.get('name', stix_object.get('id'))}")
        return stix_object
        
    except HttpResponseError as e:
        print(f"ERROR: Failed to query Log Analytics: {e}")
        print("\nPossible issues:")
        print("1. The workspace ID may be incorrect")
        print("2. The service principal may not have 'Log Analytics Reader' permissions")
        print("3. The indicator may not exist or may be older than 90 days")
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error querying Log Analytics: {e}")
        return None


def create_revoked_indicator_from_original(original_indicator):
    """
    Create a revoked version of an indicator by preserving all original data
    and only updating the revoked status and valid_until timestamp.
    
    Args:
        original_indicator (dict): The original STIX indicator object
    
    Returns:
        dict: STIX indicator object with revoked=true
    """
    # Format timestamp as ISO 8601 with milliseconds precision
    now = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    # Create a copy of the original indicator
    revoked_indicator = original_indicator.copy()
    
    # Update only the fields needed for revocation
    revoked_indicator["modified"] = now  # Update modified timestamp
    revoked_indicator["revoked"] = True  # Mark as revoked
    revoked_indicator["valid_until"] = now  # Expire immediately
    
    return revoked_indicator


def create_revoked_indicator(stix_id, pattern, pattern_type="stix", name=None, created=None, valid_from=None):
    """
    Create a STIX indicator object with revoked=true.
    
    This is a fallback method when the original indicator cannot be queried.
    
    Args:
        stix_id (str): The STIX ID of the indicator (e.g., indicator--uuid)
        pattern (str): The STIX pattern (e.g., "[ipv4-addr:value = '1.2.3.4']")
        pattern_type (str): Pattern type, default "stix"
        name (str): Optional name for the indicator
        created (str): Original created timestamp (if known)
        valid_from (str): Original valid_from timestamp (if known)
    
    Returns:
        dict: STIX indicator object with revoked=true
    """
    # Format timestamp as ISO 8601 with milliseconds precision
    now = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    # Use original created timestamp if provided, otherwise use now
    # This is important: Sentinel may not update if created timestamp changes
    created_time = created if created else now
    
    # Use original valid_from if provided, otherwise use now
    valid_from_time = valid_from if valid_from else now
    
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": created_time,
        "modified": now,  # This should always be updated to now
        "revoked": True,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "pattern_version": "2.1",
        "valid_from": valid_from_time,
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
    
    # Use sourcesystem from config, default to "MISP" if not set
    sourcesystem = getattr(config, 'sourcesystem', 'MISP')
    
    request_body = {
        "sourcesystem": sourcesystem,
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


def interactive_mode():
    """
    Interactive CLI mode for revoking indicators.
    """
    print("\n" + "="*60)
    print("  Microsoft Sentinel Indicator Revocation Tool")
    print("="*60)
    
    while True:
        print("\nOptions:")
        print("1. Revoke indicator by STIX ID (auto-query from Sentinel)")
        print("2. Revoke indicator manually (provide all details)")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '3':
            print("\nExiting...")
            break
        elif choice == '1':
            print("\n" + "-"*60)
            print("Auto-revoke mode:")
            print("  - Provide only the STIX ID")
            print("  - Script will query Sentinel for the original indicator")
            print("  - All original data will be preserved")
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
            
            # Query the original indicator from Sentinel
            original_indicator = query_indicator_from_sentinel(stix_id)
            
            if not original_indicator:
                print("\nFailed to query indicator. Please check:")
                print("  - The STIX ID is correct")
                print("  - The workspace ID in config.py is correct")
                print("  - The service principal has 'Log Analytics Reader' role")
                continue
            
            # Create revoked version
            indicator = create_revoked_indicator_from_original(original_indicator)
            
            # Show preview
            print("\n" + "-"*60)
            print("Preview of indicator to be revoked:")
            print(json.dumps(indicator, indent=2))
            print("-"*60)
            
            confirm = input("\nConfirm revocation? (y/n): ").strip().lower()
            if confirm == 'y':
                # Get Sentinel API token
                token = get_access_token()
                upload_revoked_indicator(token, indicator)
            else:
                print("Revocation cancelled.")
                
        elif choice == '2':
            print("\n" + "-"*60)
            print("Manual revoke mode:")
            print("  - STIX ID (e.g., indicator--12345678-1234-1234-1234-123456789abc)")
            print("  - STIX Pattern (e.g., [ipv4-addr:value = '1.2.3.4'])")
            print("\nOptional (helps ensure proper update):")
            print("  - Original 'created' timestamp")
            print("  - Original 'valid_from' timestamp")
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
            created = input("Enter original 'created' timestamp (optional, ISO format, press Enter to skip): ").strip()
            valid_from = input("Enter original 'valid_from' timestamp (optional, ISO format, press Enter to skip): ").strip()
            
            # Validate timestamp format if provided
            def validate_timestamp(ts_str, field_name):
                if not ts_str:
                    return True
                try:
                    # Try parsing as ISO format
                    datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    return True
                except ValueError:
                    print(f"WARNING: Invalid ISO timestamp format for {field_name}: {ts_str}")
                    print("Expected format: YYYY-MM-DDTHH:MM:SS.sssZ (e.g., 2024-01-01T00:00:00.000Z)")
                    return False
            
            if not validate_timestamp(created, "created"):
                confirm = input("Continue with invalid timestamp? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            
            if not validate_timestamp(valid_from, "valid_from"):
                confirm = input("Continue with invalid timestamp? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            
            # Create the revoked indicator
            indicator = create_revoked_indicator(
                stix_id, 
                pattern, 
                pattern_type, 
                name if name else None,
                created if created else None,
                valid_from if valid_from else None
            )
            
            # Show preview
            print("\n" + "-"*60)
            print("Preview of indicator to be revoked:")
            print(json.dumps(indicator, indent=2))
            print("-"*60)
            
            confirm = input("\nConfirm revocation? (y/n): ").strip().lower()
            if confirm == 'y':
                # Get Sentinel API token
                token = get_access_token()
                upload_revoked_indicator(token, indicator)
            else:
                print("Revocation cancelled.")
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Revoke indicators in Microsoft Sentinel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python revoke_indicator.py
  
  # Auto-query and revoke (recommended - only requires STIX ID)
  python revoke_indicator.py --id "indicator--abc123"
  
  # Manual revoke with full details
  python revoke_indicator.py --id "indicator--abc123" --pattern "[ipv4-addr:value = '1.2.3.4']" --manual

Note: Auto-query mode requires the service principal to have 'Log Analytics Reader'
role on the Log Analytics workspace connected to your Sentinel instance.
        """
    )
    
    parser.add_argument('--id', dest='stix_id', help='STIX ID of the indicator to revoke')
    parser.add_argument('--manual', action='store_true', help='Use manual mode (requires --pattern)')
    parser.add_argument('--pattern', help='STIX pattern (required in manual mode)')
    parser.add_argument('--name', help='Name of the indicator (optional, manual mode only)')
    parser.add_argument('--pattern-type', default='stix', help='Pattern type (default: stix, manual mode only)')
    parser.add_argument('--created', help='Original created timestamp (ISO format, manual mode only)')
    parser.add_argument('--valid-from', help='Original valid_from timestamp (ISO format, manual mode only)')
    
    args = parser.parse_args()
    
    # Check if we're in command-line mode
    if args.stix_id:
        # Validate STIX ID format
        if not args.stix_id.startswith("indicator--"):
            print("WARNING: STIX ID should start with 'indicator--'")
            response = input("Continue anyway? (y/n): ").strip().lower()
            if response != 'y':
                sys.exit(1)
        
        if args.manual:
            # Manual mode - requires pattern
            if not args.pattern:
                print("ERROR: --pattern is required in manual mode")
                print("Use --help for usage information")
                sys.exit(1)
            
            print("Authenticating with Microsoft Sentinel...")
            token = get_access_token()
            print("✓ Authentication successful")
            
            # Create revoked indicator manually
            indicator = create_revoked_indicator(
                args.stix_id,
                args.pattern,
                args.pattern_type,
                args.name,
                args.created,
                args.valid_from
            )
        else:
            # Auto-query mode
            print("Auto-query mode: Retrieving indicator from Sentinel...")
            
            # Query the original indicator
            original_indicator = query_indicator_from_sentinel(args.stix_id)
            
            if not original_indicator:
                print("\nERROR: Failed to retrieve indicator from Sentinel")
                print("\nTroubleshooting:")
                print("  1. Verify the STIX ID is correct")
                print("  2. Check that sentinel_workspace_id in config.py is correct")
                print("  3. Ensure the service principal has 'Log Analytics Reader' role")
                print("  4. Try using --manual mode if auto-query doesn't work")
                sys.exit(1)
            
            # Create revoked version
            indicator = create_revoked_indicator_from_original(original_indicator)
            
            # Get Sentinel API token
            print("\nAuthenticating with Microsoft Sentinel...")
            token = get_access_token()
            print("✓ Authentication successful")
        
        # Show preview
        print("\nIndicator to be revoked:")
        print(json.dumps(indicator, indent=2))
        
        # Upload
        if upload_revoked_indicator(token, indicator):
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        # Interactive mode
        if any([args.pattern, args.name, args.pattern_type, args.created, args.valid_from]):
            print("ERROR: Additional arguments are only valid with --id")
            print("Run without arguments for interactive mode, or use --help for usage")
            sys.exit(1)
        
        interactive_mode()


if __name__ == "__main__":
    main()
