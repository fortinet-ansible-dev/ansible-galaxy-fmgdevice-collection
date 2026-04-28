#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgd_firewall_shapingprofile_shapingentries
short_description: Define shaping entries of this shaping profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    shaping-profile:
        description: Deprecated, please use "shaping_profile"
        type: str
    shaping_profile:
        description: The parameter (shaping-profile) in requested url.
        type: str
    firewall_shapingprofile_shapingentries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            burst_in_msec:
                aliases: ['burst-in-msec']
                type: int
                description: Number of bytes that can be burst at maximum-bandwidth speed.
            cburst_in_msec:
                aliases: ['cburst-in-msec']
                type: int
                description: Number of bytes that can be burst as fast as the interface can transmit.
            class_id:
                aliases: ['class-id']
                type: list
                elements: str
                description: Class ID.
            guaranteed_bandwidth_percentage:
                aliases: ['guaranteed-bandwidth-percentage']
                type: int
                description: Guaranteed bandwidth in percentage.
            id:
                type: int
                description: ID number.
                required: true
            limit:
                type: int
                description: Hard limit on the real queue size in packets.
            max:
                type: int
                description: Average queue size in packets at which RED drop probability is maximal.
            maximum_bandwidth_percentage:
                aliases: ['maximum-bandwidth-percentage']
                type: int
                description: Maximum bandwidth in percentage.
            min:
                type: int
                description: Average queue size in packets at which RED drop becomes a possibility.
            priority:
                type: str
                description: Priority.
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
                    - 'top'
            red_probability:
                aliases: ['red-probability']
                type: int
                description: Maximum probability
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Define shaping entries of this shaping profile.
      fortinet.fmgdevice.fmgd_firewall_shapingprofile_shapingentries:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        shaping_profile: <your own value>
        state: present # <value in [present, absent]>
        firewall_shapingprofile_shapingentries:
          id: 0 # Required variable, integer
          # burst_in_msec: <integer>
          # cburst_in_msec: <integer>
          # class_id: <list or string>
          # guaranteed_bandwidth_percentage: <integer>
          # limit: <integer>
          # max: <integer>
          # maximum_bandwidth_percentage: <integer>
          # min: <integer>
          # priority: <value in [low, medium, high, ...]>
          # red_probability: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-profile/{shaping-profile}/shaping-entries'
    ]
    url_params = ['device', 'vdom', 'shaping-profile']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'shaping-profile': {'type': 'str', 'api_name': 'shaping_profile'},
        'shaping_profile': {'type': 'str'},
        'firewall_shapingprofile_shapingentries': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'burst-in-msec': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cburst-in-msec': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'class-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'guaranteed-bandwidth-percentage': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'max': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'maximum-bandwidth-percentage': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'min': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'priority': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['low', 'medium', 'high', 'critical', 'top'], 'type': 'str'},
                'red-probability': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shapingprofile_shapingentries'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
