from pymisp import *
import config
from collections import defaultdict
import datetime
from RequestManager import RequestManager
from RequestObject import RequestObject, RequestObject_Event, RequestObject_Indicator, RequestObject_ThreatActor, RequestObject_Identity, RequestObject_Relationship
from constants import *
import sys
from functools import reduce
import os
import datetime
from datetime import datetime, timedelta, timezone
import logging
import requests
import json

from misp_stix_converter import MISPtoSTIX21Parser
from stix2.base import STIXJSONEncoder

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_events():
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert)
    if len(config.misp_event_filters) == 0:
        return [event['Event'] for event in misp.search(controller='events', return_format='json')]
    events_for_each_filter = [
        [event['Event'] for event in misp.search(controller='events', return_format='json', **config.misp_event_filters)]
    ]
    event_ids_for_each_filter = [set(event['id'] for event in events) for events in events_for_each_filter]
    event_ids_intersection = reduce((lambda x, y: x & y), event_ids_for_each_filter)
    return [event for event in events_for_each_filter[0] if event['id'] in event_ids_intersection]


def _graph_post_request_body_generator(parsed_events):
    for event in parsed_events:
        request_body_metadata = {
            **{field: event[field] for field in REQUIRED_GRAPH_METADATA},
            **{field: event[field] for field in OPTIONAL_GRAPH_METADATA if field in event},
            'action': config.ms_action,
            'passiveOnly': config.ms_passiveonly,
            'targetProduct': config.ms_target_product,
        }

        if len(request_body_metadata.get('threatType', [])) < 1:
            request_body_metadata['threatType'] = 'watchlist'
        if config.default_confidence:
            request_body_metadata["confidence"] = config.default_confidence
        for request_object in event['request_objects']:
            request_body = {
                **request_body_metadata.copy(),
                **request_object.__dict__,
                'tags': request_body_metadata.copy()['tags'] + request_object.__dict__['tags'],
            }
            yield request_body


def _handle_timestamp(parsed_event):
    parsed_event['lastReportedDateTime'] = str(
        datetime.fromtimestamp(int(parsed_event['lastReportedDateTime'])))


def _handle_diamond_model(parsed_event):
    for tag in parsed_event['tags']:
        if 'diamond-model:' in tag:
            parsed_event['diamondModel'] = tag.split(':')[1]


def _handle_tlp_level(parsed_event):
    for tag in parsed_event['tags']:
        if 'tlp:' in tag:
            parsed_event['tlpLevel'] = tag.split(':')[1].lower().capitalize()
        if parsed_event['tlpLevel'] == 'Clear':
            parsed_event['tlpLevel'] = 'White'
    if 'tlpLevel' not in parsed_event:
        parsed_event['tlpLevel'] = 'Red'


def _get_misp_events_stix():
    logger.info("Using the following values for MISP API call: domain: %s", config.misp_domain)
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logger.debug("Query MISP for events.")
    remaining_misp_pages = True
    misp_page = 1
    misp_object_ids = []

    while remaining_misp_pages:
        try:
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters)
                remaining_misp_pages = False # Limits are set in the misp_event_filters
            else:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if len(result) > 0:
                logger.info("Received MISP events page %s with %s events", misp_page, len(result))
                for event in result:
                    misp_event = RequestObject_Event(event["Event"], logger, config.misp_flatten_attributes)
                    try:
                        parser = MISPtoSTIX21Parser()
                        parser.parse_misp_event(misp_event.event)
                        stix_objects = parser.stix_objects
                    except Exception as e:
                        logger.error("Error when processing data in event %s from MISP %s. Most likely a MISP-STIX conversion problem.", misp_event.id, e)
                        continue
                    if config.write_parsed_eventid:
                        logger.info("Processing event %s %s", event["Event"]["id"], event["Event"]["info"])
                    for element in stix_objects:
                        if element.type in STIX_OBJECTS_API_ACCEPTED_TYPES and \
                                        element.id not in misp_object_ids:
                            misp_object = None
                            
                            if element.type == 'indicator':
                                misp_object = RequestObject_Indicator(element, misp_event, logger)
                                if misp_object.id:
                                    if misp_object.valid_until:
                                        valid_until = json.dumps(misp_object.valid_until, cls=STIXJSONEncoder).replace("\"", "")
                                        # Strip the dots from 'valid_until' to avoid date parse errors
                                        if "." in valid_until:
                                            valid_until = valid_until.split(".")[0]
                                        # There must be a "cleaner-Python" way to deal with converting these date formats
                                        if "Z" in valid_until:
                                            date_object = datetime.fromisoformat(valid_until[:-1])
                                        else:
                                            date_object = datetime.fromisoformat(valid_until)
                                        if date_object > datetime.now():
                                            if config.verbose_log:
                                                logger.debug("Add %s to list of objects to upload", misp_object.pattern)
                                            misp_object_ids.append(misp_object.id)
                                            result_set.append(misp_object._get_dict())
                                        else:
                                            logger.error("Skipping outdated indicator %s in event %s, valid_until: %s", misp_object.pattern, misp_event.id, valid_until)
                                    else:
                                        logger.error("Skipping indicator because valid_until was not set by MISP/MISP2Sentinel %s", misp_object.id)
                                else:
                                    logger.error("Unable to process indicator. Invalid indicator type or invalid valid_until date. Event %s", misp_event.id)
                            
                            elif element.type == 'threat-actor':
                                misp_object = RequestObject_ThreatActor(element, misp_event, logger)
                                if config.verbose_log:
                                    logger.debug("Add threat-actor %s to list of objects to upload", misp_object.name)
                                misp_object_ids.append(misp_object.id)
                                result_set.append(misp_object._get_dict())
                            
                            elif element.type == 'identity':
                                misp_object = RequestObject_Identity(element, misp_event, logger)
                                if config.verbose_log:
                                    logger.debug("Add identity %s to list of objects to upload", misp_object.name)
                                misp_object_ids.append(misp_object.id)
                                result_set.append(misp_object._get_dict())
                            
                            elif element.type == 'relationship':
                                misp_object = RequestObject_Relationship(element, misp_event, logger)
                                if config.verbose_log:
                                    logger.debug("Add relationship %s to list of objects to upload", misp_object.relationship_type)
                                misp_object_ids.append(misp_object.id)
                                result_set.append(misp_object._get_dict())
                
                logger.info("Processed %s STIX objects", len(result_set))
                misp_page += 1
            else:
                remaining_misp_pages = False

        except exceptions.MISPServerError as e:
            remaining_misp_pages = False
            logger.error("Error received from the MISP server %s - %s - %s", e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1])
        except Exception as e:
            remaining_misp_pages = False
            logger.error("Error when processing data from MISP %s - %s - %s", e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1])

    return result_set, len(result_set)


def _init_configuration():
    config_mapping = {
        "graph_auth": "ms_auth",
        "targetProduct": "ms_target_product",
        "action": "ms_action",
        "passiveOnly": "ms_passiveonly",
        "defaultConfidenceLevel": "default_confidence"
    }

    use_old_config = False
    for old_value in config_mapping:
        if hasattr(config, old_value):
            p = getattr(config, old_value)
            setattr(config, config_mapping[old_value], p)
            use_old_config = True

    if not hasattr(config, "log_file"):
        sys.exit("Exiting. No log file configuration setting found (log_file).")
    if not (hasattr(config, "misp_domain") and hasattr(config, "misp_key") and hasattr(config, "misp_verifycert")):
        sys.exit("Exiting. No MISP authentication configuration setting found (misp_domain, misp_key and misp_verifycert).")
    if not hasattr(config, "ms_auth"):
        sys.exit("Exiting. No Microsoft authentication configuration setting found (ms_auth).")
    if not hasattr(config, "ms_useragent"):
        config.ms_useragent = "MISP-1.0"
    if not hasattr(config, "default_confidence"):
        config.default_confidence = 50
    if not hasattr(config, "ms_passiveonly"):
        config.ms_passiveonly = False
    if not hasattr(config, "ms_target_product"):
        config.ms_target_product = "Azure Sentinel"
    if not hasattr(config, "ms_action"):
        config.ms_action = "alert"
    if not hasattr(config, "misp_event_limit_per_page"):
        config.misp_event_limit_per_page = 100
    if not hasattr(config, "days_to_expire_ignore_misp_last_seen"):
        config.days_to_expire_ignore_misp_last_seen = False
    if not hasattr(config, "misp_remove_eventreports"):
        config.misp_remove_eventreports = True
    if not hasattr(config, "sentinel_write_response"):
        config.sentinel_write_response = False
    if not hasattr(config, "write_parsed_eventid"):
        config.write_parsed_eventid = False
    if not hasattr(config, "misp_flatten_attributes"):
        config.misp_flatten_attributes = False
    if not hasattr(config, "sourcesystem"):
        config.sourcesystem = "MISP"
    if not hasattr(config, "dry_run"):
        config.dry_run = False

    return use_old_config


global _build_logger


def _build_logger():
    logger = logging.getLogger("misp2sentinel")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(config.log_file, mode="a")
    ch.setLevel(logging.INFO)
    if config.verbose_log:
        ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

def main():
    logger.info("Fetching and parsing data from MISP ...")
    logger.info("Using Microsoft Sentinel STIX Objects API")
    parsed_indicators, total_indicators = _get_misp_events_stix()
    logger.info("Received %s STIX objects in MISP", total_indicators)

    if config.dry_run:
        logger.info("Dry run. Not uploading to Sentinel")
    else:
        with RequestManager(total_indicators, logger, config.ms_auth[TENANT_ID]) as request_manager:
            logger.info("Start uploading STIX objects")
            request_manager.upload_indicators(parsed_indicators)
            logger.info("Finished uploading STIX objects")
            if config.write_parsed_indicators:
                json_formatted_str = json.dumps(parsed_indicators, indent=4)
                with open("parsed_indicators.txt", "w") as fp:
                    fp.write(json_formatted_str)


if __name__ == '__main__':
    check_for_old_config = _init_configuration()
    logger = _build_logger()

    logger.info("Start MISP2Sentinel")
    if check_for_old_config:
        logger.info("You're using an older configuration setting. Update config.py to the new configuration setting.")
    main()
    logger.info("End MISP2Sentinel")
