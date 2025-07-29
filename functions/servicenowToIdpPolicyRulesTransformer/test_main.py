import json
import logging
import unittest
from unittest.mock import patch

from crowdstrike.foundry.function import Request

def mock_handler(*args, **kwargs):
    def identity(func):
        return func
    return identity

class FnTestCase(unittest.TestCase):
    logger = logging.getLogger(__name__)
    def setUp(self):
        patcher = patch('crowdstrike.foundry.function.Function.handler', new=mock_handler)
        self.addCleanup(patcher.stop)
        self.handler_patch = patcher.start()

        import importlib
        import main
        importlib.reload(main)

    def test_transform_rules_request(self):
        from main import transform_rules
        request = Request()
        with open('./test_data/function_request_transform.json', 'r') as file:
            request.body = json.load(file)

        response = transform_rules(request, config=dict(), logger=self.logger)
        # TODO: Need to mock IDP service
        self.assertEqual(502, response.code)

    def test_from_request_with_complete_data(self):
        """Test creation from a complete request body."""
        # Create a mock request body with all fields
        request_body = {
            'latestSysUpdatedOn': '2023-05-15T10:30:00Z',
            'cmdbAppNameColumn': 'app_name',
            'userGuidColumn': 'user_id',
            'hostGuidColumn': 'host_id',
            'sysUpdatedOnColumn': 'updated_at',
            'idpEnabledColumn': 'idp_enabled',
            'idpActionColumn': 'idp_action',
            'idpTriggerColumn': 'idp_trigger',
            'idpRuleNamePrefix': 'SNOW_',
            'idpSimulationModeColumn': 'idp_simulation_mode',
            'result': {
                'result': {
                    'id': '12345',
                    'name': 'Test Result'
                }
            }
        }

        from main import TransformRequest
        # Create the transform request
        transform_request = TransformRequest.from_request(request_body)

        # Assert all fields are correctly set
        self.assertEqual(transform_request.latest_sys_updated_on, '2023-05-15T10:30:00Z')
        self.assertEqual(transform_request.cmdb_app_name_column, 'app_name')
        self.assertEqual(transform_request.user_guid_column, 'user_id')
        self.assertEqual(transform_request.host_guid_column, 'host_id')
        self.assertEqual(transform_request.sys_updated_on_column, 'updated_at')
        self.assertEqual(transform_request.idp_enabled_column, 'idp_enabled')
        self.assertEqual(transform_request.idp_action_column, 'idp_action')
        self.assertEqual(transform_request.idp_trigger_column, 'idp_trigger')
        self.assertEqual(transform_request.idp_rule_name_prefix, 'SNOW_')
        self.assertEqual(transform_request.idp_simulation_mode_column, 'idp_simulation_mode')

        # Assert result is correctly extracted
        self.assertEqual(transform_request.result['id'], '12345')
        self.assertEqual(transform_request.result['name'], 'Test Result')

    def test_idp_create_rule(self):
        #test idp create rule data class
        # Sample JSON data
        input_policy_dict = {
          "name": "ServiceNow_App 1",
          "action": "BLOCK",
          "trigger": "access",
          "destination": {
            "entityId": {
              "exclude": ["1", "2"],
              "include": ["3", "4"]
            },
            "groupMembership": {
              "exclude": ["group1"],
              "include": ["group2"]
            }
          },
          "activity": {
            "accessType": {
              "exclude": ["AUTH"],
              "include": ["RDP"]
            },
            "accessTypeCustom": {
              "exclude": ["CUSTOM1"],
              "include": ["CUSTOM2"]
            }
          },
          "enabled": True,
          "simulationMode": False,
          "sourceEndpoint": {
            "entityId": {
              "exclude": ["endpoint1"],
              "include": ["endpoint2"]
            },
            "groupMembership": {
              "include": ["endpointGroup1"]
            }
          },
          "sourceUser": {
            "entityId": {
              "exclude": ["user1"],
              "include": ["user2"]
            },
            "groupMembership": {
              "exclude": ["userGroup1"],
              "include": ["userGroup2"]
            }
          }
        }


        from main import IdpCreatePolicyRuleRequest
        # Create PolicyRule instance from dictionary
        policy_rule = IdpCreatePolicyRuleRequest.from_dict(input_policy_dict)

        # Convert back to dictionary
        policy_dict = policy_rule.to_dict()

        self.assertEqual(input_policy_dict, policy_dict)


if __name__ == '__main__':
    unittest.main()