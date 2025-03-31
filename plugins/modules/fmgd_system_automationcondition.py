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
module: fmgd_system_automationcondition
short_description: Condition for automation stitches.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    system_automationcondition:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            condition_type:
                aliases: ['condition-type']
                type: str
                description: Condition type.
                choices:
                    - 'cpu'
                    - 'memory'
                    - 'vpn'
                    - 'input'
            cpu_usage_percent:
                aliases: ['cpu-usage-percent']
                type: int
                description: CPU usage reaches specified percentage.
            description:
                type: str
                description: Description.
            input_id:
                aliases: ['input-id']
                type: int
                description: Input ID.
            input_state:
                aliases: ['input-state']
                type: str
                description: Input state.
                choices:
                    - 'close'
                    - 'open'
            mem_usage_percent:
                aliases: ['mem-usage-percent']
                type: int
                description: Memory usage reaches specified percentage.
            name:
                type: str
                description: Name.
                required: true
            vdom:
                type: list
                elements: str
                description: Virtual domain which the tunnel belongs to.
            vpn_tunnel_name:
                aliases: ['vpn-tunnel-name']
                type: str
                description: VPN tunnel name.
            vpn_tunnel_state:
                aliases: ['vpn-tunnel-state']
                type: str
                description: VPN tunnel state.
                choices:
                    - 'tunnel-up'
                    - 'tunnel-down'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Condition for automation stitches.
      fortinet.fmgdevice.fmgd_system_automationcondition:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_automationcondition:
          name: "your value" # Required variable, string
          # condition_type: <value in [cpu, memory, vpn, ...]>
          # cpu_usage_percent: <integer>
          # description: <string>
          # input_id: <integer>
          # input_state: <value in [close, open]>
          # mem_usage_percent: <integer>
          # vdom: <list or string>
          # vpn_tunnel_name: <string>
          # vpn_tunnel_state: <value in [tunnel-up, tunnel-down]>
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
        '/pm/config/device/{device}/global/system/automation-condition'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_automationcondition': {
            'type': 'dict',
            'v_range': [['7.6.2', '']],
            'options': {
                'condition-type': {'v_range': [['7.6.2', '']], 'choices': ['cpu', 'memory', 'vpn', 'input'], 'type': 'str'},
                'cpu-usage-percent': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'description': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'input-id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'input-state': {'v_range': [['7.6.2', '']], 'choices': ['close', 'open'], 'type': 'str'},
                'mem-usage-percent': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'vdom': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'vpn-tunnel-name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vpn-tunnel-state': {'v_range': [['7.6.2', '']], 'choices': ['tunnel-up', 'tunnel-down'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_automationcondition'),
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
