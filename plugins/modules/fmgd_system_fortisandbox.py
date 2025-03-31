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
module: fmgd_system_fortisandbox
short_description: Configure FortiSandbox.
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
    system_fortisandbox:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            email:
                type: str
                description: Notifier email address.
            enc_algorithm:
                aliases: ['enc-algorithm']
                type: str
                description: Configure the level of SSL protection for secure communication with FortiSandbox.
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
            forticloud:
                type: str
                description: Enable/disable FortiSandbox Cloud.
                choices:
                    - 'disable'
                    - 'enable'
            inline_scan:
                aliases: ['inline-scan']
                type: str
                description: Enable/disable FortiSandbox inline scan.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            server:
                type: str
                description: Server IP address or FQDN of the remote FortiSandbox.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address for communications to FortiSandbox.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            status:
                type: str
                description: Enable/disable FortiSandbox.
                choices:
                    - 'disable'
                    - 'enable'
            ca:
                type: list
                elements: str
                description: The CA that signs remote FortiSandbox certificate, empty for no check.
            cn:
                type: str
                description: The CN of remote server certificate, case sensitive, empty for no check.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Configure FortiSandbox.
      fortinet.fmgdevice.fmgd_system_fortisandbox:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_fortisandbox:
          # email: <string>
          # enc_algorithm: <value in [default, high, low, ...]>
          # forticloud: <value in [disable, enable]>
          # inline_scan: <value in [disable, enable]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # server: <string>
          # source_ip: <string>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # status: <value in [disable, enable]>
          # ca: <list or string>
          # cn: <string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/global/system/fortisandbox'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_fortisandbox': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'email': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'enc-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'high', 'low', 'disable'], 'type': 'str'},
                'forticloud': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'inline-scan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ca': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'cn': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fortisandbox'),
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
