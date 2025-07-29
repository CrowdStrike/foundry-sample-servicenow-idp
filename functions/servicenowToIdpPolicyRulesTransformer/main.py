import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import IdentityProtection

from logging import Logger
import json

func = Function.instance()

@func.handler(method='POST', path='/transform')
def transform_rules(request: Request, config: [dict[str, any], None], logger: Logger) -> Response:
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
    logger.info("/transform")
    return _transform_rules(logger, config, request)


def _transform_rules(logger, config, request):
    if 'result' not in request.body or 'result' not in request.body['result']:
        return Response(
            code=400,
            errors=[APIError(code=400, message='result array is missing in the request body')]
        )

    transform_request = TransformRequest.from_request(request.body)
    latest_sys_updated_on = transform_request.latest_sys_updated_on


    identity_protection = IdentityProtection(access_token=request.access_token)
    # To test locally
    #identity_protection = IdentityProtection(client_id="client-id-value", client_secret="client-secret-value")

    status_code = 200
    response_body = {
        "latestSysUpdatedOn": "",
        "lastSyncTime": "",
        "deleted": 0,
        "deletedPolicyRules": list(),
        "new": 0,
        "newPolicyRules": list(),
        "updated": 0,
        "updatedPolicyRules": list(),
        "ignoredSysIdCount": 0,
        "errors": {
            "description": "",
            "errs": list()
        }
    }
    merged_result = merge_apps_access(logger, transform_request, response_body)
    for idp_policy_rule_name in merged_result:
        # Query IDP for current rule
        # Merge or Create new IDP rule request
        # delete and create the rule
        # update counts
        operation_type = 'UNMODIFIED'
        idp_create_rule_request = IdpCreatePolicyRuleRequest()

        # check for idp rule ID
        idp_policy_rule_id, errs = get_idp_policy_rule_id(logger, identity_protection, idp_policy_rule_name)
        if errs:
            logger.error("Error getting IDP policy rule ID: %s", errs)
            response_body['errors']['errs'] = errs
            response_body['errors']['description'] = ("Error getting IDP policy rule ID for policy rule: "
                                                      + idp_policy_rule_name)
            status_code = 502
            break

        copy_from_cmdb_response_to_idp_create_request(idp_create_rule_request.destination.entityId, idp_create_rule_request.sourceUser.entityId,
                                                      merged_result[idp_policy_rule_name])
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
        idp_create_rule_request.trigger = merged_result[idp_policy_rule_name]['trigger']
        idp_create_rule_request.action = merged_result[idp_policy_rule_name]['action']
        idp_create_rule_request.enabled = merged_result[idp_policy_rule_name]['enabled']
        idp_create_rule_request.simulationMode = merged_result[idp_policy_rule_name]['simulation_mode']

        if rule_conditions is not None:
            # Process rule conditions
            for condition in rule_conditions:
                # Copy from existing condition to idp create request
                if 'destination' in condition:
                    if 'entityId' in condition['destination']:
                        add_to_idp_request_from_rule_condition(idp_create_rule_request.destination.entityId,
                                                               condition['destination']['entityId'])
                    if 'groupMembership' in condition['destination']:
                        add_to_idp_request_from_rule_condition(idp_create_rule_request.destination.groupMembership,
                                                               condition['destination']['groupMembership'])
                if 'sourceUser' in condition:
                    if 'entityId' in condition['sourceUser']:
                        add_to_idp_request_from_rule_condition(idp_create_rule_request.sourceUser.entityId,
                                                               condition['sourceUser']['entityId'])
                    if 'groupMembership' in condition['sourceUser']:
                        add_to_idp_request_from_rule_condition(idp_create_rule_request.sourceUser.groupMembership,
                                                               condition['sourceUser']['groupMembership'])
            operation_type = 'UPDATED'

            # Delete existing policy
            deleted_rules = identity_protection.delete_policy_rules(parameters={'ids': idp_policy_rule_id})
            if deleted_rules['status_code'] != 200:
                errs = deleted_rules['body']['errors'] if deleted_rules and 'body' in deleted_rules and 'errors' in \
                                                          deleted_rules['body'] else None
                logger.error("Error deleting IDP policy rule details: %s", errs)
                response_body['errors']['errs'] = errs
                response_body['errors'][
                    'description'] = "Error deleting IDP policy rule details for ID - " + idp_policy_rule_id + " and policy rule name - " + idp_policy_rule_name
                status_code = 502
                break
            logger.info("deleted policy - " + str(idp_policy_rule_id))
        else:
            # create new rule
            logger.info("Create new rule")
            operation_type = 'NEW'

        idp_create_rule_request.name = idp_policy_rule_name
        # create policy rule
        created_rule = identity_protection.create_policy_rule(body=idp_create_rule_request.to_dict())
        if created_rule['status_code'] != 200:
            errs = created_rule['body']['errors'] if created_rule and 'body' in created_rule and 'errors' in \
                                                     created_rule['body'] else None
            logger.error("Error creating IDP policy rule details: %s", errs)
            response_body['errors']['errs'] = errs
            response_body['errors'][
                'description'] = "Error creating IDP policy rule details for policy rule name - " + idp_policy_rule_name
            status_code = 502
            break
        if is_timestamp_latest(latest_sys_updated_on, merged_result[idp_policy_rule_name]['latestSysUpdatedOn']):
            latest_sys_updated_on = merged_result[idp_policy_rule_name]['latestSysUpdatedOn']

        if operation_type == 'NEW':
            response_body['new'] += 1
            if idp_policy_rule_name not in response_body['newPolicyRules']:
                response_body['newPolicyRules'].append(idp_policy_rule_name)
        elif operation_type == 'UPDATED':
            response_body['updated'] += 1
            if idp_policy_rule_name not in response_body['updatedPolicyRules']:
                response_body['updatedPolicyRules'].append(idp_policy_rule_name)
    response_body['lastSyncTime'] = get_current_time()
    if latest_sys_updated_on:
        response_body['latestSysUpdatedOn'] = latest_sys_updated_on
    logger.info(f"Response body to return: {json.dumps(response_body)}")
    return Response(
        body=response_body,
        code=status_code,
    )


def get_current_time():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'

def parse_servicenow_timestamp(timestamp):
    """Parse a ServiceNow timestamp into a datetime object"""
    if 'T' in timestamp and 'Z' in timestamp:
        # ISO format
        return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    else:
        # ServiceNow format: "YYYY-MM-DD HH:MM:SS"
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

def is_timestamp_latest(stored_timestamp, new_timestamp) -> bool:
    """Compare timestamps and return true if latest"""
    return not stored_timestamp or parse_servicenow_timestamp(new_timestamp) > parse_servicenow_timestamp(stored_timestamp)

def merge_apps_access(logger, transform_request, response_body) -> dict:
    """
    Merges and aggregates application access information from ServiceNow records.

    This function processes records from the request body, filtering out records older than
    the latest_sys_updated_on timestamp. For valid records, it creates a consolidated dictionary
    keyed by application name (prefixed with the value provided by the transform_request), collecting unique user GUIDs and host GUIDs
    for each application, while tracking the most recent update timestamp.

    Args:
        logger: Logger instance for reporting issues
        transform_request: Request object containing records and other parameters
        response_body: Dictionary to track counts of ignored records

    Returns:
        Dictionary mapping application names to their aggregated access information
    """
    reduced = dict()
    for r in transform_request.result:
        if transform_request.cmdb_app_name_column not in r or transform_request.user_guid_column not in r or transform_request.host_guid_column not in r or transform_request.sys_updated_on_column not in r:
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
    errs = None
    if idp_policy_rule_id is not None and len(idp_policy_rule_id) > 0:
        if len(idp_policy_rule_id) > 0:
            if len(idp_policy_rule_id) > 1:
                logger.info("More than one policy rule Id is provided - " + idp_policy_rule_id + ". Using the first one " + idp_policy_rule_id[0])

            idp_policy_rule_id = idp_policy_rule_id[0]
            logger.info("get_policy_rules for - " + idp_policy_rule_id)
            response_body['idpPolicyRuleId'] = idp_policy_rule_id
            # get IDP policy rule details
            policy_rules = identity_protection.get_policy_rules(parameters={'ids': idp_policy_rule_id})
            #logger.info("Received policy_rules = " + json.dumps(policy_rules))
            if (policy_rules is not None and policy_rules['status_code'] == 200 and policy_rules['body'] is not None and 'resources' in policy_rules['body']
                    and len(policy_rules['body']['resources']) > 0):
                if len(policy_rules['body']['resources']) > 1:
                    logger.info("Found multiple policies. size - " + str(
                        len(policy_rules['body']['resources'])) + ". Choosing first policy.")
                rule_conditions = policy_rules['body']['resources'][0]['ruleConditions']
            if policy_rules and policy_rules['status_code'] != 200:
                errs = policy_rules['body']['errors'] if policy_rules and 'body' in policy_rules and 'errors' in policy_rules[
                    'body'] else None
    return rule_conditions, errs


# def copy_from_cmdb_response_to_idp_create_request(destination_entity_id, source_user_entity_id, entities):
#     destination_entity_id['include'] = merge_lists_unique_ordered(destination_entity_id['include'], list(entities['host_guid']))
#     source_user_entity_id['exclude'] = merge_lists_unique_ordered(source_user_entity_id['exclude'], list(entities['user_guid']))


def copy_from_cmdb_response_to_idp_create_request(destination_entity_id, source_user_entity_id, entities):
    destination_entity_id.include = merge_lists_unique_ordered(destination_entity_id.include, list(entities['host_guid']))
    source_user_entity_id.exclude = merge_lists_unique_ordered(source_user_entity_id.exclude, list(entities['user_guid']))


def add_to_idp_request_from_rule_condition(idp_request_entity, rule_entity):
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


@func.handler(method='GET', path='/healthz')
def healthz(request, config):
    return Response(code=200)

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
        result_data = dict()
        if 'result' in request_body and 'result' in request_body['result']:
            result_data = request_body['result']['result']
        return cls(
            result = result_data,
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
    entityId: FilterCriteria = field(default_factory=FilterCriteria)
    groupMembership: FilterCriteria = field(default_factory=FilterCriteria)

@dataclass
class Activity:
    """Class representing activity filtering."""
    accessType: FilterCriteria = field(default_factory=FilterCriteria)
    accessTypeCustom: FilterCriteria = field(default_factory=FilterCriteria)

@dataclass
class SourceEndpointGroupMembership:
    """Class for source endpoint group membership (only has include)."""
    include: List[str] = field(default_factory=list)

@dataclass
class SourceEndpoint:
    """Class representing source endpoint filtering."""
    entityId: FilterCriteria = field(default_factory=FilterCriteria)
    groupMembership: SourceEndpointGroupMembership = field(default_factory=SourceEndpointGroupMembership)

@dataclass
class SourceUser:
    """Class representing source user filtering."""
    entityId: FilterCriteria = field(default_factory=FilterCriteria)
    groupMembership: FilterCriteria = field(default_factory=FilterCriteria)

@dataclass
class IdpCreatePolicyRuleRequest:
    """Main class representing the complete policy rule."""
    name: str = ""
    action: str = ""
    trigger: str = ""
    destination: Destination = field(default_factory=Destination)
    activity: Activity = field(default_factory=Activity)
    enabled: bool = True
    simulationMode: bool = True
    sourceEndpoint: SourceEndpoint = field(default_factory=SourceEndpoint)
    sourceUser: SourceUser = field(default_factory=SourceUser)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IdpCreatePolicyRuleRequest':
        """Create a PolicyRule instance from a dictionary."""
        rule = cls(
            name=data.get('name', ''),
            action=data.get('action', ''),
            trigger=data.get('trigger', ''),
            enabled=data.get('enabled', False),
            simulationMode=data.get('simulationMode', False)
        )

        # Process destination
        if 'destination' in data:
            dest_data = data['destination']
            if 'entityId' in dest_data:
                rule.destination.entityId = FilterCriteria(
                    exclude=dest_data['entityId'].get('exclude', []),
                    include=dest_data['entityId'].get('include', [])
                )
            if 'groupMembership' in dest_data:
                rule.destination.groupMembership = FilterCriteria(
                    exclude=dest_data['groupMembership'].get('exclude', []),
                    include=dest_data['groupMembership'].get('include', [])
                )

        # Process activity
        if 'activity' in data:
            act_data = data['activity']
            if 'accessType' in act_data:
                rule.activity.accessType = FilterCriteria(
                    exclude=act_data['accessType'].get('exclude', []),
                    include=act_data['accessType'].get('include', [])
                )
            if 'accessTypeCustom' in act_data:
                rule.activity.accessTypeCustom = FilterCriteria(
                    exclude=act_data['accessTypeCustom'].get('exclude', []),
                    include=act_data['accessTypeCustom'].get('include', [])
                )

        # Process sourceEndpoint
        if 'sourceEndpoint' in data:
            se_data = data['sourceEndpoint']
            if 'entityId' in se_data:
                rule.sourceEndpoint.entityId = FilterCriteria(
                    exclude=se_data['entityId'].get('exclude', []),
                    include=se_data['entityId'].get('include', [])
                )
            if 'groupMembership' in se_data:
                rule.sourceEndpoint.groupMembership = SourceEndpointGroupMembership(
                    include=se_data['groupMembership'].get('include', [])
                )

        # Process sourceUser
        if 'sourceUser' in data:
            su_data = data['sourceUser']
            if 'entityId' in su_data:
                rule.sourceUser.entityId = FilterCriteria(
                    exclude=su_data['entityId'].get('exclude', []),
                    include=su_data['entityId'].get('include', [])
                )
            if 'groupMembership' in su_data:
                rule.sourceUser.groupMembership = FilterCriteria(
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
                    'exclude': self.destination.entityId.exclude,
                    'include': self.destination.entityId.include
                },
                'groupMembership': {
                    'exclude': self.destination.groupMembership.exclude,
                    'include': self.destination.groupMembership.include
                }
            },
            'activity': {
                'accessType': {
                    'exclude': self.activity.accessType.exclude,
                    'include': self.activity.accessType.include
                },
                'accessTypeCustom': {
                    'exclude': self.activity.accessTypeCustom.exclude,
                    'include': self.activity.accessTypeCustom.include
                }
            },
            'enabled': self.enabled,
            'simulationMode': self.simulationMode,
            'sourceEndpoint': {
                'entityId': {
                    'exclude': self.sourceEndpoint.entityId.exclude,
                    'include': self.sourceEndpoint.entityId.include
                },
                'groupMembership': {
                    'include': self.sourceEndpoint.groupMembership.include
                }
            },
            'sourceUser': {
                'entityId': {
                    'exclude': self.sourceUser.entityId.exclude,
                    'include': self.sourceUser.entityId.include
                },
                'groupMembership': {
                    'exclude': self.sourceUser.groupMembership.exclude,
                    'include': self.sourceUser.groupMembership.include
                }
            }
        }

if __name__ == '__main__':
    func.run()
