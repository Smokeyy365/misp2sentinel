# MISP to Microsoft Sentinel

> **Important:** This version uses the **new Upload Indicators API** (STIX objects upload API). If you want the old Microsoft Graph API approach, check out the [old-msgraph branch](https://github.com/cudeso/misp2sentinel/tree/old-msgraph).
>
> If you do not want to use the new Upload Indicators API, set `new_upload_api` to `False` in your configuration. Note that the old approach is going to be deprecated by Microsoft.

## Introduction

MISP2Sentinel uploads threat intelligence indicators from a [MISP](https://www.misp-project.org/) instance to [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/). It uses the [STIX objects upload API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api) (`https://api.ti.sentinel.azure.com`) to push indicators in STIX 2.1 format.

The script queries MISP for events via [PyMISP](https://github.com/MISP/PyMISP), converts the attributes to STIX indicator objects and sends them to Sentinel in batches. Indicators appear in the Sentinel Threat Intelligence blade and can be used in analytics rules, hunting queries and workbooks.

![docs/misp2sentinel.png](docs/misp2sentinel.png)

MISP2Sentinel is also available through the [Microsoft Sentinel Content Hub](https://portal.azure.com/#create/microsoftsentinelcommunity.azure-sentinel-solution-misp2sentinel).

![docs/misp2sentinel-1.png](docs/misp2sentinel-1.png)

## Prerequisites

- **Python 3** (3.10 or later recommended)
- A running **MISP** instance with API access
- An **Azure tenant** with a Microsoft Sentinel workspace
- An **Azure App registration** with the Microsoft Sentinel Contributor role

## Installation

### 1. Azure setup

#### Register an Azure App

Register a new application in the Microsoft [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).

1. Sign in to the [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
2. Choose **New registration**.
3. Enter an application name and choose **Register**.
   ![docs/misp2sentinel_appreg1.png](/docs/misp2sentinel_appreg1.png)
4. Note the **Application (client) ID** and the **Directory (tenant) ID**.
5. Under **Manage** > **Certificates & secrets**, choose **New client secret** and add a description. Copy the secret value straight away; it will not be shown again.

#### Assign permissions

The Azure App needs the **Microsoft Sentinel Contributor** role on each workspace you want to connect to.

1. Navigate to the **Log Analytics workspace** you wish to connect to.
2. Select **Access control (IAM)**.
3. Select **Add** > **Add role assignment**.
4. In the **Role** tab, select **Microsoft Sentinel Contributor** > **Next**.
5. On the **Members** tab, select **Assign access to** > **User, group, or service principal**.
6. Click **Select members**. Microsoft Entra applications are not shown by default, so search for your application by name.
7. Select **Review + assign**.
8. Take note of the **Workspace ID**. You can find it on the **Overview** page of the workspace.

![docs/misp2sentinel-workspaceroles.png](docs/misp2sentinel-workspaceroles.png)

#### Install the data connector

1. Go to the **Sentinel** service in the Azure portal.
2. Choose the **workspace** where you want to import indicators.
3. Under **Content management**, click **Content hub**.
4. Find and select the **MISP2Sentinel** solution.
5. Click **Install/Update**.

#### Azure Function (optional)

Instead of running the script on a server or alongside MISP, you can run it as an Azure Function. See [AzureFunction/README.MD](AzureFunction/README.MD) for instructions. The Azure Function supports the same indicator upload and cleanup features as the standalone script; the cleanup features are configured via environment variables (see [Indicator cleanup](AzureFunction/README.MD#indicator-cleanup)).

### 2. MISP setup

#### API key

MISP2Sentinel needs an API key to read events from MISP. Create one under **Global Actions** > **My Profile** > **Auth keys**. The key can be set to *read-only* because the integration does not modify any MISP data.

### 3. Python environment

1. Verify that `python3` is installed on your system.
2. Clone the repository:
   ```
   git clone https://github.com/cudeso/misp2sentinel.git
   cd misp2sentinel
   ```
3. Create and activate a virtual environment:
   ```
   virtualenv sentinel
   source sentinel/bin/activate
   ```
4. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration

All settings live in `config.py`. Copy the provided `config.py.default` to `config.py` and fill in the values described below.

If you set the environment variable **`key_vault_name`** to the name of your Azure Key Vault, the script will attempt to read secrets from there first. Otherwise it falls back to environment variables and finally to the values in `config.py` itself.

### Microsoft settings

The `ms_auth` dictionary holds the connection details for Sentinel. Fill in the `tenant` (Directory ID), `client_id` (Application client ID), `client_secret` (secret value) and `workspace_id` from the Azure setup steps above.

`new_upload_api` **must** be set to `True`. This is the only supported upload method going forward; the legacy Graph API has been deprecated by Microsoft and will be removed in a future release.

```python
ms_auth = {
    'tenant': '<tenant>',
    'client_id': '<client_id>',
    'client_secret': '<client_secret>',
    'new_upload_api': True,
    'scope': 'https://management.azure.com/.default',
    'workspace_id': '<workspace_id>',
}
```

### API settings

```python
ms_api_version = "2024-02-01-preview"
ms_delete_api_version = "2025-09-01"
ms_max_indicators_request = 100     # Maximum indicators per request (max 100)
ms_max_requests_minute = 100        # Maximum requests per minute (max 100)
```

- `ms_api_version`: The STIX objects upload API version. Leave this at `"2024-02-01-preview"`.
- `ms_delete_api_version`: The management API version used by `--verify-recent-toids-change`, `--delete-outdated-indicators` and `delete-from-azure.py`. Leave this at `"2025-09-01"` unless Microsoft publishes a newer stable version.
- `ms_max_indicators_request`: How many indicators to include in a single API call. The API allows at most 100.
- `ms_max_requests_minute`: How many API calls to make per minute. The API allows at most 100. Combined, these settings give a maximum throughput of roughly 10,000 indicators per minute.

### MISP settings

```python
misp_key = '<misp_api_key>'
misp_domain = '<misp_url>'
misp_verifycert = False
```

- `misp_key`: The MISP API key you created earlier.
- `misp_domain`: The full URL of your MISP instance, for example `https://misp.example.com`.
- `misp_verifycert`: Set to `True` if your MISP instance uses a trusted TLS certificate, or `False` to skip certificate validation (common with self-signed certificates).

### MISP event filters

The `misp_event_filters` dictionary controls which MISP events are fetched. Recommended settings:

```python
misp_event_filters = {
    "published": 1,
    "tags": [ "workflow:state=\"complete\""],
    "enforceWarninglist": True,
    "includeEventTags": True,
    "publish_timestamp": "14d",
}
```

- `"published": 1` fetches only published events.
- `"tags"` lets you restrict to events with specific tags, such as a workflow state.
- `"enforceWarninglist": True` skips indicators that match a MISP warninglist entry. This is strongly recommended, but depends on your warninglists being enabled.
- `"includeEventTags": True` carries event-level tags over to individual indicators, giving them more context in Sentinel.
- `"publish_timestamp": "14d"` fetches events published in the last 14 days.

**A note on `publish_timestamp`**: use 14 days (or more) for the initial run so that you backfill your Sentinel workspace. After that, **set this value to match your synchronisation frequency**. If you run the script every 12 hours, set it to `"12h"`. There is no benefit in re-fetching older events that have already been uploaded.

### Pagination

```python
misp_event_limit_per_page = 500
```

This setting controls how many events are fetched per MISP query. Lower it if the script consumes too much memory.

### Indicator expiry

```python
days_to_expire = 50
days_to_expire_start = "valid_from"   # "valid_from" or "current_date"
```

- `days_to_expire`: Number of days after which an indicator expires in Sentinel.
- `days_to_expire_start`: Whether the expiry is calculated from the indicator's `valid_from` timestamp or from the current date.

You can override the expiry per indicator type using `days_to_expire_mapping`:

```python
days_to_expire_mapping = {
    "ipv4-addr": 1,
    "ipv6-addr": 1,
    "domain-name": 1,
    "url": 1,
    "file:hashes": 1,
}
```

If `days_to_expire_ignore_misp_last_seen` is set to `True` (the default), the script ignores the `last_seen` value from MISP and always calculates expiry using `days_to_expire`. Set it to `False` to honour the MISP `last_seen` date where available.

### Confidence

```python
default_confidence = 50
```

Sets the default STIX confidence value (0-100) for indicators. This can be overridden per indicator through MISP tags that use the `misp-confidence` taxonomy.

#### MISP Decay Model integration

If your MISP instance uses the [Decay Model](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/), the connector can request attribute decay scores for a specific MISP decaying model, use the returned score as the confidence value sent to Sentinel, and optionally exclude indicators whose score has fallen below a threshold.

```python
misp_decaying_model = 1                     # MISP decaying model ID used for attribute decay scores
misp_decaying_score_as_confidence = False   # Use the MISP decay score as the Sentinel confidence value
misp_decaying_score_threshold = None        # Set to None to disable decay score-based filtering
                                            # Set to a value >= 0 to exclude indicators with a decay score <= this threshold
                                            # Example: 10 excludes indicators with a decay score of 10 or lower
```
- `misp_decaying_model`: MISP decaying model ID used when requesting attribute decay scores. The default is `1`. Available model IDs can be listed in MISP under `/decayingModel/index`.
- `misp_decaying_score_as_confidence`: When set to `True`, the MISP decay score of an attribute is used as the STIX confidence value (0-100) sent to Sentinel.
- `misp_decaying_score_threshold`: Attributes with a decay score less than or equal to this value are excluded from upload. Set it to `None` (default) to disable this filtering entirely. Set it to `0` to exclude indicators whose decay score has reached zero (fully decayed). A typical starting value is `10`.

> **Note:** The default decaying model ID is `1`. Decaying model IDs are instance-specific, so if your MISP instance uses another model you should update `misp_decaying_model` accordingly. You can list available models in MISP at `/decayingModel/index`.

**Priority order for confidence (highest to lowest):**

| Priority | Source | Condition |
|---|---|---|
| 1 | MISP decay score | `misp_decaying_score_as_confidence = True` and a score is available |
| 2 | MISP `misp-confidence` taxonomy tag | Tag present and no decay score applied |
| 3 | `default_confidence` | Fallback when neither of the above applies |

> **Note:** When `misp_decaying_score_as_confidence` is set to `True`, the decay score takes precedence over any `misp-confidence` taxonomy tag, if a score is available. If no decay score is returned for an attribute, the script falls back to the confidence derived from MISP tags, or to `default_confidence` if no confidence tag is present.
>
> **Note:** Threshold filtering only applies when a decay score is available. Attributes without a decay score are not excluded by `misp_decaying_score_threshold`.
>
> **Note:** If MISP returns the same attribute UUID multiple times, the script keeps the highest decay score found for that UUID.

### Other settings

```python
sourcesystem = "MISP"               # Source system name sent to Sentinel
verbose_log = False                 # Enable debug-level logging
log_file = "misp2sentinel.log"      # Path to the log file
dry_run = False                     # Process indicators without uploading them
write_parsed_indicators = False     # Write parsed indicators to parsed_indicators.txt
write_parsed_eventid = False        # Log event IDs being processed
sentinel_write_response = False     # Write Sentinel API responses to sentinel_response.txt
remove_pipe_from_misp_attribute = True  # Strip composite attributes (e.g. filename|sha256) to the first value
ignore_localtags = True             # Skip MISP tags marked as local
misp_flatten_attributes = True      # Flatten MISP object attributes into the event attribute list
misp_remove_eventreports = True     # Remove event reports from MISP events before processing
timeframe_toids_change = "1d"           # Timeframe for --verify-recent-toids-change
ms_useragent = "MISP-1.0"           # User-Agent header sent to the Sentinel API
ms_check_if_exist_in_sentinel = False   # Check if an indicator already exists in Sentinel before uploading
```

- `write_parsed_eventid`: When set to `True`, the script logs the event IDs it processes. Useful for debugging which events are being picked up by the filters.
- `misp_remove_eventreports`: When set to `True`, event reports attached to MISP events are stripped before processing. Defaults to `True`.
- `timeframe_toids_change`: The MISP search timeframe used by `--verify-recent-toids-change`. Defaults to `"1d"`. Accepts the same formats as MISP timestamps (e.g. `"12h"`, `"7d"`).
- `ms_useragent`: The User-Agent string sent with API requests. Defaults to `"MISP-1.0"`.
- `ms_check_if_exist_in_sentinel`: When set to `True`, the script checks whether each indicator already exists in Sentinel before uploading. This avoids duplicates but adds an API call per indicator, which slows down the synchronisation. Requires `subscription_id`, `resourceGroupName` and `workspaceName` in `ms_auth` (see the [deleting indicators](#deleting-indicators-when-to_ids-changes) section).

## Running the script

Make sure the virtual environment is active, then run:

```
python script.py
```

You can also process a single MISP event by passing its UUID:

```
python script.py --uuid <event-uuid>
```

### Deleting indicators when to_ids changes

When an analyst sets the `to_ids` flag to `False` on a MISP attribute, the corresponding indicator should no longer be in Sentinel. Use the `--verify-recent-toids-change` flag to find these attributes and delete the matching indicators in Sentinel:

```
python script.py --verify-recent-toids-change
```

This queries MISP for attributes where `to_ids` was recently set to `False`, looks them up in Sentinel and deletes them. Only indicators whose source matches `sourcesystem` (default `"MISP"`) are considered, so indicators from other feeds are never affected. The timeframe is controlled by `timeframe_toids_change` in `config.py` (default: `"1d"`). The flag can be combined with `--uuid`.

Set `dry_run = True` to preview which indicators would be deleted without actually removing them.

### Deleting outdated indicators

Use the `--delete-outdated-indicators` flag to remove indicators whose `validUntil` date has passed:

```
python script.py --delete-outdated-indicators
```

This queries Sentinel for all indicators from the configured `sourcesystem` whose `validUntil` is in the past, and deletes them. The flag can be combined with `--uuid`.

Set `dry_run = True` to preview which indicators would be deleted without actually removing them.

### How indicator deletion works

Indicators are deleted by calling the Microsoft Sentinel ThreatIntelligence management API:

```
DELETE https://management.azure.com/subscriptions/{subscriptionId}
       /resourceGroups/{resourceGroupName}
       /providers/Microsoft.OperationalInsights/workspaces/{workspaceName}
       /providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators/{name}
       ?api-version=2025-09-01
```

The indicator immediately disappears from the Sentinel **Threat Intelligence** blade and from `queryIndicators` results. Note that the underlying `ThreatIntelligenceIndicator` row in the Log Analytics workspace is **not** physically removed: its `IsDeleted` column flips from `false` to `true`. Hunting queries should filter on `IsDeleted == false` to ignore deleted indicators.

The DELETE call requires the `subscription_id`, `resourceGroupName` and `workspaceName` keys to be set in `ms_auth`. The API version is configurable via `ms_delete_api_version` in `config.py` (default: `"2025-09-01"`).

Both `--verify-recent-toids-change` and `--delete-outdated-indicators` use this DELETE mechanism.

### Verifying your configuration

Use `check-config.py` to test connectivity to both MISP and Azure before running the main script:

```
python check-config.py
```

This will attempt to authenticate against MISP (and fetch one event) and obtain an access token from Azure, reporting any issues.

### Scheduling

To keep Sentinel up to date, schedule the script with cron (Linux) or Task Scheduler (Windows). For example, to run every hour:

```
0 * * * * cd /path/to/misp2sentinel && sentinel/bin/python script.py
```

## Azure Key Vault integration (optional)

If you run the script on an Azure VM, you can store secrets in Azure Key Vault instead of keeping them in `config.py`.

1. Enable a managed identity for the virtual machine.
2. Create an Azure Key Vault.
3. Add the secrets `MISP-Key` and `ClientSecret` in the Key Vault secrets tab.
4. Give the VM's managed identity the `Reader` role on the Key Vault.
5. Give the same managed identity `Get` and `List` permissions in the Key Vault access policy.
6. Make sure the Key Vault libraries are installed (they are included in `requirements.txt`):
   - `azure-keyvault-secrets`
   - `azure-identity`

Then uncomment and configure the Key Vault section in `config.py`:

```python
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

keyVaultName = "<unique-name>"
KVUri = f"https://{keyVaultName}.vault.azure.net"

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KVUri, credential=credential)

retrieved_mispkey = client.get_secret('MISP-Key')
retrieved_clientsecret = client.get_secret('ClientSecret')
```

After that, update the relevant variables to use the retrieved values:

```python
misp_key = retrieved_mispkey.value
```

```python
'client_secret': retrieved_clientsecret.value
```

## Integration details

### MISP taxonomies

To get the most out of the Sentinel integration, enable the following MISP taxonomies:

- [MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp) (used for confidence levels)
- [sentinel-threattype](https://www.misp-project.org/taxonomies.html#_sentinel_threattype) (mapped to STIX `indicator_types`)
- [kill-chain](https://www.misp-project.org/taxonomies.html#_kill_chain) (mapped to STIX kill chain phases)
- [Decay Model](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/) (optional — used for decay-score-based confidence and filtering)

These taxonomies are not required for the integration to work, but they add useful context for analysts working with the indicators in Sentinel.

### How tags are mapped

#### Confidence level

The default confidence value (set in `default_confidence`) can be overridden per indicator using the MISP confidence taxonomy. The tag is translated to a numerical value as defined by `MISP_CONFIDENCE` in `constants.py`.
If `misp_decaying_score_as_confidence` is enabled and a decay score is available for the attribute, the decay score overrides the confidence derived from the taxonomy tag.

![docs/Taxonomies_-_MISP.png](docs/Taxonomies_-_MISP.png)

#### Sentinel threat type

You can tag events or attributes with the [sentinel-threattype](https://www.misp-project.org/taxonomies.html#_sentinel_threattype) taxonomy. The integration maps these tags to STIX [indicator_types](https://stixproject.github.io/data-model/1.2/indicator/IndicatorType/), which Sentinel displays as the threat type.

#### Kill chain

[Kill chain tags](https://www.misp-project.org/taxonomies.html#_kill_chain) are translated to STIX kill chain phases following the Lockheed Martin Cyber Kill Chain model.

#### TLP

TLP (Traffic Light Protocol) tags on events and attributes are translated to STIX marking definitions. An attribute-level TLP takes precedence over an event-level TLP. If no TLP tag is set at all, `tlp:white` is applied by default (configurable via `SENTINEL_DEFAULT_TLP` in `constants.py`).

![docs/attribute-tags-demo.png](docs/attribute-tags-demo.png)

![docs/attribute-tags-demo-sentinel.png](docs/attribute-tags-demo-sentinel.png)

![docs/attribute-tags-demo-sentinel2.png](docs/attribute-tags-demo-sentinel2.png)

### Controlling which tags are synchronised

You can control which tags get synchronised using two variables in `constants.py`:

- **`MISP_TAGS_IGNORE`**: A list of tag prefixes to exclude. It already contains the default tags added during STIX conversion, but you can extend it with your own entries.
- **`MISP_ALLOWED_TAXONOMIES`**: A list of allowed taxonomy prefixes. Only tags belonging to these taxonomies will be included. Leave the list empty to allow all taxonomies. For example: `["tlp", "admiralty-scale", "type"]`.

#### MISP galaxies and clusters

In MISP, galaxies and clusters (such as threat actors, malware families or ATT&CK techniques) are internally represented as tags. By default, galaxy tags are **not** synchronised to Sentinel because `MISP_TAGS_IGNORE` contains the `"misp-galaxy:"` prefix. This keeps the indicator labels in Sentinel concise.

If you want galaxy and cluster tags to appear on your Sentinel indicators, remove `"misp-galaxy:"` from the `MISP_TAGS_IGNORE` list in `constants.py`.

### Supported indicator types

Only attributes with a STIX pattern type are synchronised. Attributes of type `yara` or `sigma`, for instance, are skipped. The list of accepted MISP attribute types is defined by `UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES` in `constants.py`.

#### Custom attribute types

If you want to synchronise MISP attribute types that do not have a native STIX pattern (such as `iban`), you can add them to the `MISP_CUSTOM_ATTRIBUTE` frozenset in `constants.py`. These attributes are sent to Sentinel as freetext indicators, similar to the freetext indicator you can create manually in the Azure portal.

Requirements:

- The attribute must have the **to_ids** flag set in MISP.
- The attribute type must be listed in `MISP_CUSTOM_ATTRIBUTE`.

This is useful for indicator types like IBAN numbers, phone numbers or other identifiers that are not part of the STIX standard but that you still want to track in Sentinel.

### "Created by" in Sentinel

The "Created by" field in Sentinel refers to the UUID of the MISP organisation that created the event. Because Sentinel does not yet fully support STIX identity objects, this appears as a textual reference rather than a linked entity.

### Flattening object attributes

When `misp_flatten_attributes` is set to `True`, the script extracts all attributes from MISP objects and treats them as standalone attributes. This means you lose some contextual information (although a comment is added noting which object the attribute belonged to), but it ensures that every attribute that can be converted to a STIX indicator is synchronised.

## Network access

MISP2Sentinel requires outbound HTTPS (port 443) access to the hosts listed below. In a corporate environment with a proxy or firewall, make sure these domains are whitelisted.

| Domain | Required | Used for |
|--------|----------|----------|
| Your MISP instance (e.g. `misp.example.com`) | Always | Fetching events and attributes via the MISP API |
| `login.microsoftonline.com` | Always | Azure AD OAuth2 token acquisition |
| `api.ti.sentinel.azure.com` | When `new_upload_api` is `True` | Uploading STIX indicators to Sentinel |
| `sentinelus.azure-api.net` | When `new_upload_api` is `False` (legacy) | Uploading indicators via the legacy API |
| `management.azure.com` | When using `ms_check_if_exist_in_sentinel`, `--verify-recent-toids-change` or `delete-from-azure.py` | Querying and deleting indicators in Sentinel |

If you use Azure Key Vault for secret storage, also allow access to your vault endpoint (`<vault-name>.vault.azure.net`).

## Troubleshooting

### My indicator does not appear in Sentinel

Check the following:

- Is the MISP event **published**?
- Is the `to_ids` flag set to `True` on the attribute?
- Is the attribute type one of the supported types (listed in `UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES` in `constants.py`)?
- Has the `valid_until` date already passed? Expired indicators are skipped.

### My indicators are being skipped unexpectedly

If indicators that have `to_ids = True` are not being uploaded, check whether `misp_decaying_score_threshold` is set to a value other than `None`. Attributes with a decay score less than or equal to this threshold are excluded from the upload. Set it to `None` to disable this filtering entirely, or lower the threshold value.

Also verify that `misp_decaying_model` matches a valid decaying model ID on your MISP instance. The default is `1`, but another model may be more appropriate depending on your configuration.

You can enable `verbose_log = True` to see which indicators are being skipped and why.

### My indicators all have the same confidence value

If all indicators show `default_confidence` in Sentinel despite having decay scores in MISP, check the following:

- Is `misp_decaying_score_as_confidence` set to `True` in `config.py`?
- Does the MISP API response include a `decay_score` entry for the attributes, with a usable `score` value?
- Is the Decay Model enabled in MISP and applied to the events you are synchronising?
- Is `misp_decaying_model` set to a valid decaying model ID for your MISP instance?

### Error: KeyError: 'access_token'

This means the Azure authentication failed. Double-check that `tenant`, `client_id`, `client_secret` and `workspace_id` are correct.

### How do I find the tenant, client_id and workspace_id?

- **`tenant`** is the Directory (tenant) ID. Search for *Tenant Properties* in the Azure portal.
- **`client_id`** is the Application (client) ID. Find it under *App Registrations* in the Azure portal.
- **`workspace_id`** is the Workspace ID shown on the *Overview* page of your Log Analytics workspace.

### Getting copies of requests and responses

- Set `write_parsed_indicators = True` to write the STIX indicators sent to Sentinel to `parsed_indicators.txt`. This file is overwritten on each run.
- Set `sentinel_write_response = True` to write error responses from Sentinel to `sentinel_response.txt`.

### Help with MISP event filters

- The blog post [Figuring out MISP2Sentinel Event Filters](https://www.infernux.no/MISP2Sentinel-EventFilters/) walks through common filter configurations.
- The MISP playbook [Using timestamps in MISP](https://github.com/MISP/misp-playbooks/blob/main/misp-playbooks/pb_using_timestamps_in_MISP-with_output.ipynb) explains time-based filters in detail.
- The [MISP OpenAPI specification](https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents) for event search documents all available filter parameters.

## Additional resources

- [MISP and Microsoft Sentinel](https://www.vanimpe.eu/2022/04/20/misp-and-microsoft-sentinel/)
- [Integrating open source threat feeds with MISP and Sentinel](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371)
- [MISP2Sentinel update](https://www.infernux.no/MicrosoftSentinel-MISP2SentinelUpdate/)
- [Microsoft Sentinel STIX objects API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api)

