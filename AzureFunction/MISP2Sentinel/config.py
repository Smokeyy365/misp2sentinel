import os
import json 

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

mispkey = ''
mispurl=os.getenv('mispurl')

local_mode=os.getenv('local_mode', 'False')
keyVaultName=os.getenv('key_vault_name', '')

tenant_id=os.getenv('tenant_id', '')
workspace_id=os.getenv('workspace_id', '')
client_id=os.getenv('client_id', '')
client_secret=os.getenv('client_secret', '')
subscription_id=os.getenv('subscription_id', '')
resource_group_name=os.getenv('resource_group_name', '')
workspace_name=os.getenv('workspace_name', '')

# MS API settings
ms_auth = {
    'tenant': tenant_id,
    'client_id': client_id,
    'client_secret': client_secret,
    'new_upload_api': True,
    'scope': 'https://management.azure.com/.default',
    'graph_api': False,
    'workspace_id': workspace_id,
    'subscription_id': subscription_id,
    'resourceGroupName': resource_group_name,
    'workspaceName': workspace_name,
}

## If Azure Key Vault name variable is set, use it for secret values
if not keyVaultName == '':
    # Key vault section
    # Key Vault name must be a globally unique DNS name
    
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    
    # Log in with the virtual machines managed identity
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)
    
    # Retrieve values from KV (client secret, MISP-key most importantly)
    retrieved_mispkey = client.get_secret('MISP-Key')
    retrieved_clientsecret = client.get_secret('ClientSecret')
    
    # Set values with 
    mispkey = retrieved_mispkey.value
    ms_auth['client_secret'] = retrieved_clientsecret.value
else:
    print('key_vault_name env variable not set, falling back to env variable for config values....')
    mispkey=os.getenv('mispkey')

#####################
# Microsoft Section #
#####################

ms_max_indicators_request = 100     # Throttle max: 100 indicators per request
ms_max_requests_minute = 100        # Throttle max: 100 requests per minute
ms_useragent = 'MISP-1.0'
ms_target_product = 'Azure Sentinel'    # targetProduct
ms_api_version = "2024-02-01-preview"       # Upload Indicators API version
ms_delete_api_version = os.getenv('ms_delete_api_version', '2025-09-01')   # Management API version used to delete indicators

# Graph API only settings
ms_passiveonly = False                  # passiveOnly
ms_action = 'alert'                     # action

################
# MISP Section #
################

# MISP API settings
misp_key = mispkey
misp_domain = mispurl
misp_verifycert = local_mode.strip().lower() != 'true'

# MISP Event filters
if os.getenv('misp_event_filters', None):
    misp_event_filters_raw = os.getenv('misp_event_filters')
    try:
        misp_event_filters = json.loads(misp_event_filters_raw)
    except json.JSONDecodeError:
        raise RuntimeError("Error parsing misp_event_filters. Make sure the content is a valid JSON object.")
else:
    misp_event_filters = {
        "published": 1,
        "publish_timestamp": "14d",
        "enforceWarninglist": True,
        "includeEventTags": True
    }

# MISP pagination settings
misp_event_limit_per_page = 100      # Limit memory use when querying MISP for STIX packages

# Cleanup / deletion features (opt-in via env vars)
sourcesystem = os.getenv('sourcesystem', 'MISP')
dry_run = os.getenv('dry_run', 'False').strip().lower() == 'true'
enable_verify_toids_change = os.getenv('enable_verify_toids_change', 'False').strip().lower() == 'true'
enable_delete_outdated_indicators = os.getenv('enable_delete_outdated_indicators', 'False').strip().lower() == 'true'
timeframe_toids_change = os.getenv('timeframe_toids_change', '1d')

########################
# Integration settings #
########################

log_file = "/tmp/misp2sentinel.log"
verbose_log = False
write_parsed_indicators = False      # Upload Indicators only

# Graph API only settings
ignore_localtags = True 
network_ignore_direction = True
write_post_json = False 


# IOC settings
default_confidence = 50
days_to_expire = 30
days_to_expire_start = "current_date" # Upload Indicators API only. Start counting from "valid_from" | "current_date" ; 
days_to_expire_mapping = {          # Upload indicators API only. Mapping for expiration of specific indicator types
                        "ipv4-addr": 180,
                        "ipv6-addr": 180,
                        "domain-name": 300,
                        "url": 400
                    }
misp_flatten_attributes = True 