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
module: fmgd_wanopt_cacheservice
short_description: Designate cache-service for wan-optimization and webcache.
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
    wanopt_cacheservice:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            acceptable_connections:
                aliases: ['acceptable-connections']
                type: str
                description: Set strategy when accepting cache collaboration connection.
                choices:
                    - 'any'
                    - 'peers'
            collaboration:
                type: str
                description: Enable/disable cache-collaboration between cache-service clusters.
                choices:
                    - 'disable'
                    - 'enable'
            device_id:
                aliases: ['device-id']
                type: str
                description: Set identifier for this cache device.
            dst_peer:
                aliases: ['dst-peer']
                type: list
                elements: dict
                description: Dst peer.
                suboptions:
                    auth_type:
                        aliases: ['auth-type']
                        type: int
                        description: Set authentication type for this peer.
                    device_id:
                        aliases: ['device-id']
                        type: str
                        description: Device ID of this peer.
                    encode_type:
                        aliases: ['encode-type']
                        type: int
                        description: Set encode type for this peer.
                    ip:
                        type: str
                        description: Set cluster IP address of this peer.
                    priority:
                        type: int
                        description: Set priority for this peer.
            prefer_scenario:
                aliases: ['prefer-scenario']
                type: str
                description: Set the preferred cache behavior towards the balance between latency and hit-ratio.
                choices:
                    - 'balance'
                    - 'prefer-speed'
                    - 'prefer-cache'
            src_peer:
                aliases: ['src-peer']
                type: list
                elements: dict
                description: Src peer.
                suboptions:
                    auth_type:
                        aliases: ['auth-type']
                        type: int
                        description: Set authentication type for this peer.
                    device_id:
                        aliases: ['device-id']
                        type: str
                        description: Device ID of this peer.
                    encode_type:
                        aliases: ['encode-type']
                        type: int
                        description: Set encode type for this peer.
                    ip:
                        type: str
                        description: Set cluster IP address of this peer.
                    priority:
                        type: int
                        description: Set priority for this peer.
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
    - name: Designate cache-service for wan-optimization and webcache.
      fortinet.fmgdevice.fmgd_wanopt_cacheservice:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        wanopt_cacheservice:
          # acceptable_connections: <value in [any, peers]>
          # collaboration: <value in [disable, enable]>
          # device_id: <string>
          # dst_peer:
          #   - auth_type: <integer>
          #     device_id: <string>
          #     encode_type: <integer>
          #     ip: <string>
          #     priority: <integer>
          # prefer_scenario: <value in [balance, prefer-speed, prefer-cache]>
          # src_peer:
          #   - auth_type: <integer>
          #     device_id: <string>
          #     encode_type: <integer>
          #     ip: <string>
          #     priority: <integer>
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
        '/pm/config/device/{device}/global/wanopt/cache-service'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'wanopt_cacheservice': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'acceptable-connections': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['any', 'peers'], 'type': 'str'},
                'collaboration': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-peer': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'encode-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'prefer-scenario': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['balance', 'prefer-speed', 'prefer-cache'], 'type': 'str'},
                'src-peer': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'encode-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_cacheservice'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
