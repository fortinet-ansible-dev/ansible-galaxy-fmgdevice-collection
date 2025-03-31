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
module: fmgd_azure_vwanslb
short_description: Configure Azure vWAN slb setting.
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
    azure_vwanslb:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            mode:
                type: str
                description: Mode of VWAN SLB setting.
                choices:
                    - 'active'
                    - 'passive'
            permanent_security_rules:
                aliases: ['permanent-security-rules']
                type: dict
                description: Permanent security rules.
                suboptions:
                    rules:
                        type: list
                        elements: dict
                        description: Rules.
                        suboptions:
                            applies_on:
                                aliases: ['applies-on']
                                type: str
                                description: Applies on target.
                            destination_port_ranges:
                                aliases: ['destination-port-ranges']
                                type: str
                                description: Destination port ranges.
                            name:
                                type: str
                                description: Name of security rule.
                            protocol:
                                type: str
                                description: Protocol.
                                choices:
                                    - 'TCP'
                                    - 'UDP'
                            source_address_prefix:
                                aliases: ['source-address-prefix']
                                type: str
                                description: Source address ranges.
                    status:
                        type: str
                        description: Status of SLB inbound security rules setting
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'pending'
                            - 'updating'
                    version:
                        type: int
                        description: Version of SLB setting
                    type:
                        type: int
                        description: Type of security rules
            temporary_security_rules:
                aliases: ['temporary-security-rules']
                type: dict
                description: Temporary security rules.
                suboptions:
                    expiration_time:
                        aliases: ['expiration-time']
                        type: str
                        description: Expiration time
                    rules:
                        type: list
                        elements: dict
                        description: Rules.
                        suboptions:
                            destination_port_ranges:
                                aliases: ['destination-port-ranges']
                                type: str
                                description: Destination port ranges.
                            name:
                                type: str
                                description: Name of security rule.
                            protocol:
                                type: str
                                description: Protocol.
                                choices:
                                    - 'TCP'
                                    - 'UDP'
                            source_address_prefix:
                                aliases: ['source-address-prefix']
                                type: str
                                description: Source address ranges.
                    status:
                        type: str
                        description: Status of SLB inbound security rules setting
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'pending'
                            - 'updating'
                    type:
                        type: int
                        description: Type of security rules
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
    - name: Configure Azure vWAN slb setting.
      fortinet.fmgdevice.fmgd_azure_vwanslb:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        azure_vwanslb:
          # mode: <value in [active, passive]>
          # permanent_security_rules:
          #   rules:
          #     - applies_on: <string>
          #       destination_port_ranges: <string>
          #       name: <string>
          #       protocol: <value in [TCP, UDP]>
          #       source_address_prefix: <string>
          #   status: <value in [disable, enable, pending, ...]>
          #   version: <integer>
          #   type: <integer>
          # temporary_security_rules:
          #   expiration_time: <string>
          #   rules:
          #     - destination_port_ranges: <string>
          #       name: <string>
          #       protocol: <value in [TCP, UDP]>
          #       source_address_prefix: <string>
          #   status: <value in [disable, enable, pending, ...]>
          #   type: <integer>
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
        '/pm/config/device/{device}/global/azure/vwan-slb'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'azure_vwanslb': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'mode': {'v_range': [['7.4.3', '']], 'choices': ['active', 'passive'], 'type': 'str'},
                'permanent-security-rules': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'rules': {
                            'v_range': [['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'applies-on': {'v_range': [['7.4.3', '']], 'type': 'str'},
                                'destination-port-ranges': {'v_range': [['7.4.3', '']], 'type': 'str'},
                                'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                                'protocol': {'v_range': [['7.4.3', '']], 'choices': ['TCP', 'UDP'], 'type': 'str'},
                                'source-address-prefix': {'v_range': [['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'pending', 'updating'], 'type': 'str'},
                        'version': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'type': {'v_range': [['7.4.4', '']], 'type': 'int'}
                    }
                },
                'temporary-security-rules': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'expiration-time': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'rules': {
                            'v_range': [['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'destination-port-ranges': {'v_range': [['7.4.3', '']], 'type': 'str'},
                                'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                                'protocol': {'v_range': [['7.4.3', '']], 'choices': ['TCP', 'UDP'], 'type': 'str'},
                                'source-address-prefix': {'v_range': [['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'pending', 'updating'], 'type': 'str'},
                        'type': {'v_range': [['7.4.4', '']], 'type': 'int'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'azure_vwanslb'),
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
