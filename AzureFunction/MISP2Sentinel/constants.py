ATTR_MAPPING = {
    'AS': 'networkSourceAsn',
    'email-dst': 'emailRecipient',
    'email-src-display-name': 'emailSenderName',
    'email-subject': 'emailSubject',
    'email-x-mailer': 'emailXMailer',
    'filename': 'fileName',
    'malware-type': 'malwareFamilyNames',
    'mutex': 'fileMutexName',
    'port': 'networkPort',
    'published': 'isActive',
    'size-in-bytes': 'fileSize',
    'url': 'url',
    'user-agent': 'userAgent',
    'uuid': 'externalId',
    'domain': 'domainName',
    'hostname': 'domainName'
}

MISP_HASH_TYPES = frozenset([
    "filename|authentihash",
    "filename|impfuzzy",
    "filename|imphash",
    "filename|md5",
    "filename|pehash",
    "filename|sha1",
    "filename|sha224",
    "filename|sha256",
    "filename|sha384",
    "filename|sha512",
    "filename|sha512/224",
    "filename|sha512/256",
    "filename|ssdeep",
    "filename|tlsh",
    "authentihash",
    "impfuzzy",
    "imphash",
    "md5",
    "pehash",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512/224",
    "sha512/256",
    "ssdeep",
    "tlsh",
])

MISP_SPECIAL_CASE_TYPES = frozenset([
    *MISP_HASH_TYPES,
    'url',
    'ip-dst',
    'ip-src',
    'domain|ip',
    'email-src',
    'ip-dst|port',
    'ip-src|port'
])

MISP_ACTIONABLE_TYPES = frozenset([
    *ATTR_MAPPING.keys(),
    *MISP_SPECIAL_CASE_TYPES
])


CLIENT_ID = 'client_id'
CLIENT_SECRET = 'client_secret'
TENANT_ID = 'tenant_id'
SCOPE = 'scope'
USER_AGENT = 'user-agent'
ACCESS_TOKEN = 'access_token'
WORKSPACE_ID = 'workspace_id'
LOG_DIRECTORY_NAME = '/tmp/logs'
EXISTING_INDICATORS_HASH_FILE_NAME = '/tmp/existing_indicators_hash'
EXPIRATION_DATE_TIME = 'expirationDateTime'
EXPIRATION_DATE_FILE_NAME = '/tmp/expiration_date'
INDICATOR_REQUEST_HASH = 'indicatorRequestHash'
STIX_OBJECTS_API_ACCEPTED_TYPES = frozenset([
    'indicator',
    'threat-actor',
    'identity',
    'relationship'
])
UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES = list(MISP_ACTIONABLE_TYPES)
TLP_MARKING_OBJECT_DEFINITION={"tlp:white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                                    "tlp:clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                                    "tlp:green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                                    "tlp:amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                                    "tlp:amber+strict": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                                    "tlp:red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}

EVENT_MAPPING = {
    'date': 'firstReportedDateTime',
    'timestamp': 'lastReportedDateTime',
    'info': 'description',
    'uuid': 'externalId'
}

MISP_TAGS_IGNORE = ["misp-galaxy:", "Threat-Report", "misp:tool=\"MISP-STIX-Converter\"", "misp:to_ids=\"True\"", "misp:to_ids=\"False\"", "misp:category=", "misp:name=", "misp:meta-category=", "misp:category=", "misp:type="]
MISP_ALLOWED_TAXONOMIES = [] # empty list for all taxonomies ["tlp", "admiralty-scale", "type"]
MISP_CONFIDENCE = {"prefix": "misp:confidence-level", "matches": {"completely-confident": 100, "confidence-cannot-be-evalued": 50, "fairly-confident": 50, "rarely-confident": 25, "unconfident": 0, "usually-confident": 75}}
MISP_ANALYSIS = {0: "Initial", 1: "Ongoing", 2: "Completed"}
MISP_THREATLEVEL = {1: "Low", 2: "Medium" , 3: "High", 4: "Unknown"}
SENTINEL_DEFAULT_THREATTYPE = "WatchList"
SENTINEL_DEFAULT_TLP = "tlp:white"