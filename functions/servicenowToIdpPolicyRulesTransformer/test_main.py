"""
This test validates function
"""
import importlib
import json
import logging
import unittest
from unittest.mock import patch, MagicMock

from crowdstrike.foundry.function import Request

import main

def mock_handler(*args, **kwargs): # pylint: disable=unused-argument
    """Mock func"""
    def identity(func):
        return func
    return identity

class FnTestCase(unittest.TestCase):
    """
    Function test suite
    """
    logger = logging.getLogger(__name__)
    def setUp(self):
        patcher = patch('crowdstrike.foundry.function.Function.handler', new=mock_handler)
        self.addCleanup(patcher.stop)
        self.handler_patch = patcher.start()

        importlib.reload(main)

    def test_transform_rules_request(self):
        """
        test transform rules request
        """
        request = Request()
        with open('./test_data/function_request_transform.json', 'r', encoding='utf-8') as file:
            request.body = json.load(file)

        response = main.get_table_data_transform_rules(request, config={}, logger=self.logger)
        # Need to mock IDP service - expects authentication error from ServiceNow API
        self.assertEqual(401, response.code)

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

        # Create the transform request
        transform_request = main.TransformRequest.from_request(request_body)

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
        """test idp create rule data class"""
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


        # Create PolicyRule instance from dictionary
        policy_rule = main.IdpCreatePolicyRuleRequest.from_dict(input_policy_dict)

        # Convert back to dictionary
        policy_dict = policy_rule.to_dict()

        self.assertEqual(input_policy_dict, policy_dict)

    def test_parse_link_header(self):
        """Test parsing of Link header for pagination"""
        link_header = '<https://example.com/next>; rel="next", <https://example.com/last>; rel="last"'
        parsed_links = main.parse_link_header(link_header)
        
        self.assertEqual(parsed_links['next'], 'https://example.com/next')
        self.assertEqual(parsed_links['last'], 'https://example.com/last')

    def test_get_query_param_from_url(self):
        """Test extracting query parameters from URL"""
        url = "https://example.com/api?sysparm_offset=20&sysparm_limit=10"
        offset = main.get_query_param_from_url(url, 'sysparm_offset')
        limit = main.get_query_param_from_url(url, 'sysparm_limit')
        
        self.assertEqual(offset, ['20'])
        self.assertEqual(limit, ['10'])

    def test_is_timestamp_latest(self):
        """Test timestamp comparison logic"""
        # Test with empty stored timestamp
        self.assertTrue(main.is_timestamp_latest("", "2025-05-13 20:09:59"))
        
        # Test with newer timestamp
        self.assertTrue(main.is_timestamp_latest("2025-05-12 20:09:59", "2025-05-13 20:09:59"))
        
        # Test with older timestamp
        self.assertFalse(main.is_timestamp_latest("2025-05-14 20:09:59", "2025-05-13 20:09:59"))
        
    def test_merge_lists_unique_ordered(self):
        """Test merging lists while preserving order and uniqueness"""
        list1 = ["a", "b", "c"]
        list2 = ["b", "d", "e"]
        result = main.merge_lists_unique_ordered(list1, list2)
        
        self.assertEqual(result, ["a", "b", "c", "d", "e"])

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_missing_required_params(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records with missing required parameters"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            # Missing tableName and latestSysUpdatedOn
        }
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        self.assertEqual(response.code, 400)
        self.assertIn("Missing required configuration", response.body['errors']['description'])
        mock_get_data.assert_not_called()
        mock_transform.assert_not_called()

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_single_page(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records with single page response"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            'apiOperationId': 'test_op',
            'tableName': 'test_table',
            'latestSysUpdatedOn': '2025-05-12 18:53:31'
        }
        
        # Mock successful ServiceNow API response with no pagination
        mock_get_data.return_value = {
            'status_code': 200,
            'body': {
                'result': [
                    {'id': '1', 'name': 'test1'},
                    {'id': '2', 'name': 'test2'}
                ]
            },
            'headers': {}  # No Link header means no pagination
        }
        
        # Mock transform response
        mock_transform_response = MagicMock()
        mock_transform.return_value = mock_transform_response
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        # Verify get_servicenow_data was called once with correct parameters
        mock_get_data.assert_called_once()
        call_args = mock_get_data.call_args[0]
        self.assertEqual(call_args[1], 'test_def')  # definition_id
        self.assertEqual(call_args[2], 'test_op')   # operation_id
        self.assertEqual(call_args[3], 'test_table') # table_name
        
        # Verify _transform_rules was called with the batch data
        mock_transform.assert_called_once()
        transform_call_args = mock_transform.call_args[0]
        self.assertEqual(transform_call_args[2], [{'id': '1', 'name': 'test1'}, {'id': '2', 'name': 'test2'}])
        
        self.assertEqual(response, mock_transform_response)

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_multiple_pages(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records with pagination"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            'apiOperationId': 'test_op',
            'tableName': 'test_table',
            'latestSysUpdatedOn': '2025-05-12 18:53:31'
        }
        
        # Mock paginated ServiceNow API responses
        responses = [
            # First page
            {
                'status_code': 200,
                'body': {
                    'result': [{'id': '1', 'name': 'test1'}]
                },
                'headers': {
                    'Link': '<https://example.com/api?sysparm_offset=1>; rel="next", <https://example.com/api?sysparm_offset=2>; rel="last"'
                }
            },
            # Second page
            {
                'status_code': 200,
                'body': {
                    'result': [{'id': '2', 'name': 'test2'}]
                },
                'headers': {
                    'Link': '<https://example.com/api?sysparm_offset=2>; rel="next", <https://example.com/api?sysparm_offset=2>; rel="last"'
                }
            },
            # Last page (next == last)
            {
                'status_code': 200,
                'body': {
                    'result': [{'id': '3', 'name': 'test3'}]
                },
                'headers': {
                    'Link': '<https://example.com/api?sysparm_offset=2>; rel="next", <https://example.com/api?sysparm_offset=2>; rel="last"'
                }
            }
        ]
        
        mock_get_data.side_effect = responses
        
        # Mock transform response
        mock_transform_response = MagicMock()
        mock_transform.return_value = mock_transform_response
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        # Verify get_servicenow_data was called 3 times (3 pages)
        self.assertEqual(mock_get_data.call_count, 3)
        
        # Verify _transform_rules was called 3 times with different batches
        self.assertEqual(mock_transform.call_count, 3)
        
        # Check that each transform call received the correct batch data
        transform_calls = mock_transform.call_args_list
        self.assertEqual(transform_calls[0][0][2], [{'id': '1', 'name': 'test1'}])
        self.assertEqual(transform_calls[1][0][2], [{'id': '2', 'name': 'test2'}])
        self.assertEqual(transform_calls[2][0][2], [{'id': '3', 'name': 'test3'}])
        
        self.assertEqual(response, mock_transform_response)

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_api_error(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records with ServiceNow API error"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            'apiOperationId': 'test_op',
            'tableName': 'test_table',
            'latestSysUpdatedOn': '2025-05-12 18:53:31'
        }
        
        # Mock ServiceNow API error response
        mock_get_data.return_value = {
            'status_code': 500,
            'errors': {
                'message': 'Internal Server Error'
            }
        }
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        self.assertEqual(response.code, 500)
        self.assertIn("ServiceNow API error: Internal Server Error", response.body['errors']['description'])
        mock_transform.assert_not_called()

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_exception_handling(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records exception handling"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            'apiOperationId': 'test_op',
            'tableName': 'test_table',
            'latestSysUpdatedOn': '2025-05-12 18:53:31'
        }
        
        # Mock an exception during API call
        mock_get_data.side_effect = Exception("Connection timeout")
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        self.assertEqual(response.code, 500)
        self.assertIn("Error in batch processing: Connection timeout", response.body['errors']['description'])
        mock_transform.assert_not_called()

    @patch('main.get_servicenow_data')
    @patch('main._transform_rules')
    def test_fetch_and_process_servicenow_records_empty_response(self, mock_transform, mock_get_data):
        """Test fetch_and_process_servicenow_records with empty result"""
        request = Request()
        request.body = {
            'apiDefinitionId': 'test_def',
            'apiOperationId': 'test_op',
            'tableName': 'test_table',
            'latestSysUpdatedOn': '2025-05-12 18:53:31'
        }
        
        # Mock successful ServiceNow API response with empty results
        mock_get_data.return_value = {
            'status_code': 200,
            'body': {
                'result': []
            },
            'headers': {}
        }
        
        # Mock transform response
        mock_transform_response = MagicMock()
        mock_transform.return_value = mock_transform_response
        
        response = main.fetch_and_process_servicenow_records(request, self.logger)
        
        # Verify _transform_rules was called with empty batch
        mock_transform.assert_called_once()
        transform_call_args = mock_transform.call_args[0]
        self.assertEqual(transform_call_args[2], [])
        
        self.assertEqual(response, mock_transform_response)


if __name__ == '__main__':
    unittest.main()
