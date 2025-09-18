"""
This module transforms ServiceNow records to IDP policy rules.
"""

import json
import logging
import re

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging import Logger
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, parse_qs

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import IdentityProtection
from falconpy import APIIntegrations

func = Function.instance()


@func.handler(method='POST', path='/get-data-transform')
def get_table_data_transform_rules(request: Request, config: Optional[Dict[str, Any]], logger: Logger) -> Response:
    """
    Transform IDP policy rules by updating or creating rule conditions.
    Gets IDP policy rules and updates them if present else creates a new IDP policy rule.

    Args:
        request: The HTTP request with
        config: Optional configuration dictionary
        logger: Logger instance for recording events

    Returns:
        Response: HTTP response with a summary of IDP Policy rule synchronization
    """

    # placeholder to use data from config
    if config:
        pass
    logger.info("/get-data-transform")
    return fetch_and_process_servicenow_records(request, logger)


def get_servicenow_data(logger, definition_id, operation_id, table_name, query, limit, offset):
    logger.debug(
        f"getting servicenow data using API-Integration. table_name:{table_name}, query: {query}, limit:{limit}, offset:{offset} ")

    # Use the APIIntegrations client to call ServiceNow Table API
    api = APIIntegrations()
    response = api.execute_command_proxy(
        definition_id=definition_id,
        operation_id=operation_id,
        params={
            "path": {"tableName": table_name},
            "query": {"sysparm_limit": limit,
                      "sysparm_query": query,
                      "sysparm_offset": offset}
        },
        request={
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        }
    )

    logger.info(f"ServiceNow API response: {response}")
    return response


def fetch_and_process_servicenow_records(request, logger=None):
    """
    Fetch ServiceNow data using Link header pagination and process each batch immediately.
    """
    try:
        # definition_id = request.body.get('apiDefinitionId', "service now cmdb")
        # operation_id = request.body.get('apiIntegrationOperationId', "GET__api_now_table_tablename")
        # table_name = request.body.get('tableName', "u_test_server_access_data")
        # query = request.body.get('sysParamQuery', "sys_updated_on>=2025-09-12 18:00:00^ORDERBYsys_updated_on")
        # limit = request.body.get('sysParamLimit', "20")

        definition_id = request.body.get('apiDefinitionId', "service now cmdb")
        operation_id = request.body.get('apiOperationId', "GET__api_now_table_tablename")
        table_name = request.body.get('tableName', "")
        latest_sys_updated_on = request.body.get('latestSysUpdatedOn', "")
        query = request.body.get('sysParamQuery',
                                 f"sys_updated_on>={request.body.get('latestSysUpdatedOn', "")}^ORDERBYsys_updated_on")
        limit = request.body.get('sysParamLimit', 500)

        offset = 0
        offset_param = 'sysparm_offset'
        next_url = None
        last_url = None
        page_count = 0
        total_processed = 0
        response_body = initialize_response_body()
        is_last_batch = False
        transform_response = {}

        if not all([definition_id, operation_id, table_name, latest_sys_updated_on]):
            response_body['errors']['description'] = "Missing required configuration: apiIntegrationDefinitionId, apiIntegrationOperationId, tableName, latestSysUpdatedOn"
            return Response(body=response_body, code=400)

        # Start with initial request
        while True:
            page_count += 1

            logger.info(f"Fetching and processing ServiceNow data - page {page_count}")

            # if next_url available, get next offset
            if next_url:
                offset = get_query_param_from_url(next_url, offset_param)

            response = get_servicenow_data(logger, definition_id, operation_id, table_name, query, limit, offset)

            if response["status_code"] != 200:
                error_msg = f"ServiceNow API error: {response.get("errors", {}).get("message", "Unknown error")}"
                logger.error(error_msg)
                response_body['errors']['description'] = error_msg
                return Response(body=response_body, code=response["status_code"])

            current_batch = response.get('body', {}).get('result', [])
            total_processed += len(current_batch)

            logger.info(f"Processing batch of {len(current_batch)} records")

            # Process batch
            transform_response = _transform_rules(logger, request, current_batch, response_body)

            # if last batch, exit loop
            if is_last_batch:
                logger.info(f"Completed processing final batch, total records processed: {total_processed}")
                break

            logger.info(f"Completed processing batch {page_count}, total records processed: {total_processed}")

            link_header = response.get('headers', {}).get('Link', '')
            if link_header:
                logger.info(f"all Links: {link_header}")

                parsed_links = parse_link_header(link_header)

                next_url = parsed_links.get('next')
                last_url = parsed_links.get('last')

                logger.debug(f"next_url: {next_url}")
                logger.debug(f"last_url: {last_url}")

                if next_url == last_url:
                    is_last_batch = True
            else:
                logger.info(f"Links response header not present; means current page has all the new records")
                break

        logger.info(f"Completed processing all batches. Total pages: {page_count}, total records: {total_processed}")
        logger.info(f"Response body to return: {transform_response}")

        return transform_response

    except Exception as e:
        error_msg = f"Error in batch processing: {str(e)}"
        logger.error(f"error_msg: {e}")
        response_body = initialize_response_body()
        response_body['errors']['description'] = error_msg
        return Response(body=response_body, code=500)


def _transform_rules(logger, request, result_data, response_body):
    transform_request = TransformRequest.from_request(request.body)
    transform_request.result = result_data
    latest_sys_updated_on = transform_request.latest_sys_updated_on

    identity_protection = IdentityProtection(access_token=request.access_token)
    # To test locally
    # identity_protection = IdentityProtection(client_id="client-id-value", client_secret="client-secret-value")
    # identity_protection = IdentityProtection(client_id="4b398c11d871422cb2d83bd1539659bd", client_secret="FfjIMxkZET7Wmg4J3C65hsoP2tible10VDL8B9KN")

    status_code = 200
    merged_result = merge_apps_access(logger, transform_request, response_body)
    for idp_policy_rule_name, access in merged_result.items():
        # Query IDP for current rule
        # Merge or Create new IDP rule request
        # delete and create the rule
        # update counts
        idp_create_rule_request = IdpCreatePolicyRuleRequest()
        initialize_idp_create_rule_request(access, idp_create_rule_request)

        # check for idp rule ID
        idp_policy_rule_id, errs = get_idp_policy_rule_id(logger, identity_protection, idp_policy_rule_name)
        if errs:
            logger.error("Error getting IDP policy rule ID: %s", errs)
            response_body['errors']['errs'] = errs
            response_body['errors']['description'] = ("Error getting IDP policy rule ID for policy rule: "
                                                      + idp_policy_rule_name)
            status_code = 502
            break

        copy_from_cmdb_response_to_idp_create_request(idp_create_rule_request.source_user.entity_id,
                                                      idp_create_rule_request.source_endpoint.entity_id,
                                                      access)
        rule_conditions = None
        # Get policy rule details
        rule_conditions, errs = get_idp_policy_rule_details(identity_protection, idp_policy_rule_id, logger,
                                                            response_body, rule_conditions)
        if errs:
            logger.error("Error getting IDP policy rule details: %s", errs)
            response_body['errors']['errs'] = errs
            response_body['errors']['description'] = ("Error getting IDP policy rule details for ID - "
                                                      + idp_policy_rule_id + " and policy rule name - "
                                                      + idp_policy_rule_name)
            status_code = 502
            break
        if 'idpPolicyRuleId' in response_body:
            response_body.pop('idpPolicyRuleId')

        if rule_conditions is not None:
            if update_idp_rule(rule_conditions, idp_create_rule_request, identity_protection, idp_policy_rule_id,
                               idp_policy_rule_name, response_body, logger) != 200:
                status_code = 502
                break
            operation_type = 'UPDATED'
        else:
            # create new rule
            logger.info("Create new rule")
            operation_type = 'NEW'

        idp_create_rule_request.name = idp_policy_rule_name
        # create policy rule
        if create_idp_rule(identity_protection, idp_create_rule_request, response_body, idp_policy_rule_name,
                           logger) != 200:
            status_code = 502
            break

        if is_timestamp_latest(latest_sys_updated_on, access['latestSysUpdatedOn']):
            latest_sys_updated_on = access['latestSysUpdatedOn']

        update_metrics_in_response_body(idp_policy_rule_name, operation_type, response_body)
    response_body['lastSyncTime'] = get_current_time()
    if latest_sys_updated_on:
        response_body['latestSysUpdatedOn'] = latest_sys_updated_on
    logger.info(f"Transform rules response body: {json.dumps(response_body)}")
    return Response(
        body=response_body,
        code=status_code,
    )


def initialize_idp_create_rule_request(access, idp_create_rule_request):
    """
    Initialize idp create rule request
    """
    idp_create_rule_request.trigger = access['trigger']
    idp_create_rule_request.action = access['action']
    idp_create_rule_request.enabled = access['enabled']
    idp_create_rule_request.simulation_mode = access['simulation_mode']


def update_metrics_in_response_body(idp_policy_rule_name, operation_type, response_body):
    """
    Update metrics in response body
    """
    if operation_type == 'NEW':
        response_body['new'] += 1
        if idp_policy_rule_name not in response_body['newPolicyRules']:
            response_body['newPolicyRules'].append(idp_policy_rule_name)
    elif operation_type == 'UPDATED':
        response_body['updated'] += 1
        if idp_policy_rule_name not in response_body['updatedPolicyRules']:
            response_body['updatedPolicyRules'].append(idp_policy_rule_name)


def initialize_response_body() -> dict:
    """
    Initialize response body
    """
    return {
        "latestSysUpdatedOn": "",
        "lastSyncTime": "",
        "deleted": 0,
        "deletedPolicyRules": [],
        "new": 0,
        "newPolicyRules": [],
        "updated": 0,
        "updatedPolicyRules": [],
        "ignoredSysIdCount": 0,
        "errors": {
            "description": "",
            "errs": []
        }
    }


def update_idp_rule(rule_conditions, idp_create_rule_request, identity_protection, idp_policy_rule_id,
                    idp_policy_rule_name, response_body, logger) -> int:
    """
    Update an existing IDP policy rule.
    """
    status_code = 200
    # Process rule conditions
    for condition in rule_conditions:
        # Copy from existing condition to idp create request
        if 'sourceEndpoint' in condition:
            if 'entityId' in condition['sourceEndpoint']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.source_endpoint.entity_id,
                                                       condition['sourceEndpoint']['entityId'])
            if 'groupMembership' in condition['sourceEndpoint']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.source_endpoint.group_membership,
                                                       condition['sourceEndpoint']['groupMembership'])

        if 'sourceUser' in condition:
            if 'entityId' in condition['sourceUser']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.source_user.entity_id,
                                                       condition['sourceUser']['entityId'])
            if 'groupMembership' in condition['sourceUser']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.source_user.group_membership,
                                                       condition['sourceUser']['groupMembership'])
        if 'destination' in condition:
            if 'entityId' in condition['destination']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.destination.entity_id,
                                                       condition['destination']['entityId'])
            if 'groupMembership' in condition['destination']:
                add_to_idp_request_from_rule_condition(idp_create_rule_request.destination.group_membership,
                                                       condition['destination']['groupMembership'])

    # Delete existing policy
    deleted_rules = identity_protection.delete_policy_rules(parameters={'ids': idp_policy_rule_id})
    if deleted_rules['status_code'] != 200:
        errs = deleted_rules['body']['errors'] if deleted_rules and 'body' in deleted_rules and 'errors' in \
                                                  deleted_rules['body'] else None
        logger.error("Error deleting IDP policy rule details: %s", errs)
        response_body['errors']['errs'] = errs
        response_body['errors'][
            'description'] = ("Error deleting IDP policy rule details for ID - " + idp_policy_rule_id
                              + " and policy rule name - " + idp_policy_rule_name)
        status_code = 502
    logger.info("deleted policy - " + str(idp_policy_rule_id))
    return status_code


def create_idp_rule(identity_protection, idp_create_rule_request, response_body, idp_policy_rule_name, logger) -> int:
    """
    Create IDP policy rule
    """
    # create policy rule
    status_code = 200
    created_rule = identity_protection.create_policy_rule(body=idp_create_rule_request.to_dict())
    if created_rule['status_code'] != 200:
        errs = created_rule['body']['errors'] if created_rule and 'body' in created_rule and 'errors' in \
                                                 created_rule['body'] else None
        logger.error("Error creating IDP policy rule details: %s", errs)
        response_body['errors']['errs'] = errs
        response_body['errors'][
            'description'] = "Error creating IDP policy rule details for policy rule name - " + idp_policy_rule_name
        status_code = 502
    return status_code


def get_query_param_from_url(url, query_param_key):
    """
    Get query param from URL
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return query_params.get(query_param_key, [])


def parse_link_header(link_header):
    """Parse Link header to extract next and last URLs"""
    try:
        links = {}

        for link in link_header.split(','):
            match = re.match(r'<([^>]+)>;\s*rel="([^"]+)"', link.strip())
            if match:
                url, rel = match.groups()
                links[rel] = url

        return links
    except Exception as e:
        return e


def get_current_time():
    """
    Get current time in ISO format
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'


def parse_servicenow_timestamp(timestamp):
    """Parse a ServiceNow timestamp into a datetime object"""
    if 'T' in timestamp and 'Z' in timestamp:
        # ISO format
        return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    # ServiceNow format: "YYYY-MM-DD HH:MM:SS"
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")


def is_timestamp_latest(stored_timestamp, new_timestamp) -> bool:
    """Compare timestamps and return true if latest"""
    return not stored_timestamp or parse_servicenow_timestamp(new_timestamp) > parse_servicenow_timestamp(
        stored_timestamp)


def merge_apps_access(logger, transform_request, response_body) -> dict:
    """
    Merges and aggregates application access information from ServiceNow records.

    This function processes records from the request body, filtering out records older than
    the latest_sys_updated_on timestamp. For valid records, it creates a consolidated dictionary
    keyed by application name (prefixed with the value provided by the transform_request), collecting unique user GUIDs
    and host GUIDs for each application, while tracking the most recent update timestamp.

    Args:
        logger: Logger instance for reporting issues
        transform_request: Request object containing records and other parameters
        response_body: Dictionary to track counts of ignored records

    Returns:
        Dictionary mapping application names to their aggregated access information
    """
    reduced = {}
    for r in transform_request.result:
        if (transform_request.cmdb_app_name_column not in r or transform_request.user_guid_column not in r
                or transform_request.host_guid_column not in r or transform_request.sys_updated_on_column not in r):
            logger.info("Missing u_cmdb_app_name or u_user_guid or u_host_guid or sys_updated_on")
            continue
        # ignore records before transform_request.sys_updated_on_column
        if is_timestamp_latest(transform_request.latest_sys_updated_on, r[transform_request.sys_updated_on_column]):
            # Create the key with provided rule name prefix and app name
            key = f"{transform_request.idp_rule_name_prefix}{r[transform_request.cmdb_app_name_column]}"
            # Add the entry to the result dictionary
            if key not in reduced:
                reduced[key] = {
                    "user_guid": set(),
                    "host_guid": set(),
                    "latestSysUpdatedOn": "",
                    "enabled": None,
                    "simulation_mode": None,
                    "action": "",
                    "trigger": ""
                }

            reduced[key]['user_guid'].add(r[transform_request.user_guid_column])
            reduced[key]['host_guid'].add(r[transform_request.host_guid_column])
            reduced[key]['enabled'] = json.loads(r[transform_request.idp_enabled_column])
            reduced[key]['simulation_mode'] = json.loads(r[transform_request.idp_simulation_mode_column])
            reduced[key]['action'] = r[transform_request.idp_action_column]
            reduced[key]['trigger'] = r[transform_request.idp_trigger_column]

            if is_timestamp_latest(reduced[key]['latestSysUpdatedOn'], r[transform_request.sys_updated_on_column]):
                reduced[key]['latestSysUpdatedOn'] = r[transform_request.sys_updated_on_column]
        else:
            response_body['ignoredSysIdCount'] += 1
    return reduced


def get_idp_policy_rule_id(logger, identity_protection, rule_name):
    """
    Get the id of the policy rule
    """
    policy_ids = identity_protection.query_policy_rules(parameters={'name': rule_name})
    idp_policy_rule_id = None
    errs = None
    if policy_ids is not None and policy_ids['status_code'] == 200 and policy_ids['body'] is not None and 'resources' in \
            policy_ids['body'] and len(policy_ids['body']['resources']) > 0:
        if len(policy_ids['body']['resources']) > 1:
            logger.info("Multiple policies found - " + str(len(policy_ids['body']['resources'])) + ". Choosing " +
                        policy_ids['body']['resources'][0])
        idp_policy_rule_id = policy_ids['body']['resources'][0:1]
    else:
        if policy_ids and policy_ids['status_code'] != 200 and policy_ids['status_code'] != 404:
            errs = policy_ids['body']['errors'] if policy_ids and 'body' in policy_ids and 'errors' in policy_ids[
                'body'] else None
        logger.info("No policyId found for " + rule_name)
    return idp_policy_rule_id, errs


def get_idp_policy_rule_details(identity_protection, idp_policy_rule_id, logger, response_body, rule_conditions):
    """
    Get the policy rule details
    """
    errs = None
    if idp_policy_rule_id is not None and len(idp_policy_rule_id) > 0:
        if len(idp_policy_rule_id) > 0:
            if len(idp_policy_rule_id) > 1:
                logger.info(
                    "More than one policy rule Id is provided - " + idp_policy_rule_id + ". Using the first one "
                    + idp_policy_rule_id[0])

            idp_policy_rule_id = idp_policy_rule_id[0]
            logger.info("get_policy_rules for - " + idp_policy_rule_id)
            response_body['idpPolicyRuleId'] = idp_policy_rule_id
            # get IDP policy rule details
            policy_rules = identity_protection.get_policy_rules(parameters={'ids': idp_policy_rule_id})
            if (policy_rules is not None and policy_rules['status_code'] == 200 and policy_rules['body'] is not None
                    and 'resources' in policy_rules['body']
                    and len(policy_rules['body']['resources']) > 0):
                if len(policy_rules['body']['resources']) > 1:
                    logger.info("Found multiple policies. size - " + str(
                        len(policy_rules['body']['resources'])) + ". Choosing first policy.")
                rule_conditions = policy_rules['body']['resources'][0]['ruleConditions']
            if policy_rules and policy_rules['status_code'] != 200:
                errs = policy_rules['body']['errors'] if (policy_rules and 'body' in policy_rules
                                                          and 'errors' in policy_rules['body']) else None
    return rule_conditions, errs


def copy_from_cmdb_response_to_idp_create_request(source_user_entity_id, source_endpoint_entity_id, entities):
    """
       Copy the entities from the CMDB response to the create IDP policy rule request
    """
    source_endpoint_entity_id.exclude = merge_lists_unique_ordered(source_endpoint_entity_id.exclude,
                                                                   list(entities['host_guid']))
    source_user_entity_id.include = merge_lists_unique_ordered(source_user_entity_id.include,
                                                               list(entities['user_guid']))


def add_to_idp_request_from_rule_condition(idp_request_entity, rule_entity):
    """
    Add the rule entity to the IDP request
    """
    if 'options' in rule_entity:
        for option in rule_entity['options']:
            rule_entity_options = rule_entity['options']
            if option not in idp_request_entity.include and option not in idp_request_entity.exclude:
                if rule_entity_options[option] == "INCLUDED":
                    idp_request_entity.include.append(option)
                elif rule_entity_options[option] == "EXCLUDED":
                    idp_request_entity.exclude.append(option)
                else:
                    logging.error("Unknown option - " + rule_entity_options[option] + " - provided for " + option)


def merge_lists_unique_ordered(list1, list2):
    """
    Merge two lists without duplicates, preserving order.

    Args:
        list1 (list): First list
        list2 (list): Second list

    Returns:
        list: Combined list with unique elements, preserving order
    """
    return list(OrderedDict.fromkeys(list1 + list2))


@dataclass
class TransformRequest:
    """Configuration class to hold request parameters."""
    result: Dict[str, Any]
    latest_sys_updated_on: str
    cmdb_app_name_column: Optional[str]
    user_guid_column: Optional[str]
    host_guid_column: Optional[str]
    sys_updated_on_column: Optional[str]
    idp_enabled_column: Optional[bool]
    idp_action_column: Optional[str]
    idp_trigger_column: Optional[str]
    idp_rule_name_prefix: Optional[str]
    idp_simulation_mode_column: Optional[bool]

    @classmethod
    def from_request(cls, request_body: Dict[str, Any]) -> 'TransformRequest':
        """Create a RequestConfig instance from a request body dictionary."""
        return cls(
            latest_sys_updated_on=request_body.get('latestSysUpdatedOn', ""),
            cmdb_app_name_column=request_body.get('cmdbAppNameColumn'),
            user_guid_column=request_body.get('userGuidColumn'),
            host_guid_column=request_body.get('hostGuidColumn'),
            sys_updated_on_column=request_body.get('sysUpdatedOnColumn'),
            idp_enabled_column=request_body.get('idpEnabledColumn'),
            idp_action_column=request_body.get('idpActionColumn'),
            idp_trigger_column=request_body.get('idpTriggerColumn'),
            idp_rule_name_prefix=request_body.get('idpRuleNamePrefix'),
            idp_simulation_mode_column=request_body.get('idpSimulationModeColumn')
        )


#### IDP rule creation classes ####

@dataclass
class FilterCriteria:
    """Class representing filter criteria with include/exclude lists."""
    exclude: List[str] = field(default_factory=list)
    include: List[str] = field(default_factory=list)


@dataclass
class Destination:
    """Class representing destination filtering."""
    entity_id: FilterCriteria = field(default_factory=FilterCriteria)
    group_membership: FilterCriteria = field(default_factory=FilterCriteria)


@dataclass
class Activity:
    """Class representing activity filtering."""
    access_type: FilterCriteria = field(default_factory=FilterCriteria)
    access_type_custom: FilterCriteria = field(default_factory=FilterCriteria)


@dataclass
class SourceEndpointGroupMembership:
    """Class for source endpoint group membership (only has include)."""
    include: List[str] = field(default_factory=list)


@dataclass
class SourceEndpoint:
    """Class representing source endpoint filtering."""
    entity_id: FilterCriteria = field(default_factory=FilterCriteria)
    group_membership: SourceEndpointGroupMembership = field(default_factory=SourceEndpointGroupMembership)


@dataclass
class SourceUser:
    """Class representing source user filtering."""
    entity_id: FilterCriteria = field(default_factory=FilterCriteria)
    group_membership: FilterCriteria = field(default_factory=FilterCriteria)


@dataclass
class IdpCreatePolicyRuleRequest:
    """Main class representing the complete policy rule."""
    name: str = ""
    action: str = ""
    trigger: str = ""
    destination: Destination = field(default_factory=Destination)
    activity: Activity = field(default_factory=Activity)
    enabled: bool = True
    simulation_mode: bool = True
    source_endpoint: SourceEndpoint = field(default_factory=SourceEndpoint)
    source_user: SourceUser = field(default_factory=SourceUser)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IdpCreatePolicyRuleRequest':
        """Create a PolicyRule instance from a dictionary."""
        rule = cls(
            name=data.get('name', ''),
            action=data.get('action', ''),
            trigger=data.get('trigger', ''),
            enabled=data.get('enabled', False),
            simulation_mode=data.get('simulationMode', False)
        )

        # Process destination
        if 'destination' in data:
            dest_data = data['destination']
            if 'entityId' in dest_data:
                rule.destination.entity_id = FilterCriteria(
                    exclude=dest_data['entityId'].get('exclude', []),
                    include=dest_data['entityId'].get('include', [])
                )
            if 'groupMembership' in dest_data:
                rule.destination.group_membership = FilterCriteria(
                    exclude=dest_data['groupMembership'].get('exclude', []),
                    include=dest_data['groupMembership'].get('include', [])
                )

        # Process activity
        if 'activity' in data:
            act_data = data['activity']
            if 'accessType' in act_data:
                rule.activity.access_type = FilterCriteria(
                    exclude=act_data['accessType'].get('exclude', []),
                    include=act_data['accessType'].get('include', [])
                )
            if 'accessTypeCustom' in act_data:
                rule.activity.access_type_custom = FilterCriteria(
                    exclude=act_data['accessTypeCustom'].get('exclude', []),
                    include=act_data['accessTypeCustom'].get('include', [])
                )

        # Process sourceEndpoint
        if 'sourceEndpoint' in data:
            se_data = data['sourceEndpoint']
            if 'entityId' in se_data:
                rule.source_endpoint.entity_id = FilterCriteria(
                    exclude=se_data['entityId'].get('exclude', []),
                    include=se_data['entityId'].get('include', [])
                )
            if 'groupMembership' in se_data:
                rule.source_endpoint.group_membership = SourceEndpointGroupMembership(
                    include=se_data['groupMembership'].get('include', [])
                )

        # Process sourceUser
        if 'sourceUser' in data:
            su_data = data['sourceUser']
            if 'entityId' in su_data:
                rule.source_user.entity_id = FilterCriteria(
                    exclude=su_data['entityId'].get('exclude', []),
                    include=su_data['entityId'].get('include', [])
                )
            if 'groupMembership' in su_data:
                rule.source_user.group_membership = FilterCriteria(
                    exclude=su_data['groupMembership'].get('exclude', []),
                    include=su_data['groupMembership'].get('include', [])
                )

        return rule

    def to_dict(self) -> Dict[str, Any]:
        """Convert the PolicyRule instance to a dictionary."""
        return {
            'name': self.name,
            'action': self.action,
            'trigger': self.trigger,
            'destination': {
                'entityId': {
                    'exclude': self.destination.entity_id.exclude,
                    'include': self.destination.entity_id.include
                },
                'groupMembership': {
                    'exclude': self.destination.group_membership.exclude,
                    'include': self.destination.group_membership.include
                }
            },
            'activity': {
                'accessType': {
                    'exclude': self.activity.access_type.exclude,
                    'include': self.activity.access_type.include
                },
                'accessTypeCustom': {
                    'exclude': self.activity.access_type_custom.exclude,
                    'include': self.activity.access_type_custom.include
                }
            },
            'enabled': self.enabled,
            'simulationMode': self.simulation_mode,
            'sourceEndpoint': {
                'entityId': {
                    'exclude': self.source_endpoint.entity_id.exclude,
                    'include': self.source_endpoint.entity_id.include
                },
                'groupMembership': {
                    'include': self.source_endpoint.group_membership.include
                }
            },
            'sourceUser': {
                'entityId': {
                    'exclude': self.source_user.entity_id.exclude,
                    'include': self.source_user.entity_id.include
                },
                'groupMembership': {
                    'exclude': self.source_user.group_membership.exclude,
                    'include': self.source_user.group_membership.include
                }
            }
        }


if __name__ == '__main__':
    func.run()
