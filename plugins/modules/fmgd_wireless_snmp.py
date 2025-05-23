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
module: fmgd_wireless_snmp
short_description: Configure SNMP.
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    wireless_snmp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            community:
                type: list
                elements: dict
                description: Community.
                suboptions:
                    hosts:
                        type: list
                        elements: dict
                        description: Hosts.
                        suboptions:
                            id:
                                type: int
                                description: Host entry ID.
                            ip:
                                type: str
                                description: IPv4 address of the SNMP manager
                    id:
                        type: int
                        description: Community ID.
                    name:
                        type: str
                        description: Community name.
                    query_v1_status:
                        aliases: ['query-v1-status']
                        type: str
                        description: Enable/disable SNMP v1 queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    query_v2c_status:
                        aliases: ['query-v2c-status']
                        type: str
                        description: Enable/disable SNMP v2c queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable this SNMP community.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v1_status:
                        aliases: ['trap-v1-status']
                        type: str
                        description: Enable/disable SNMP v1 traps.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v2c_status:
                        aliases: ['trap-v2c-status']
                        type: str
                        description: Enable/disable SNMP v2c traps.
                        choices:
                            - 'disable'
                            - 'enable'
            contact_info:
                aliases: ['contact-info']
                type: str
                description: Contact Information.
            engine_id:
                aliases: ['engine-id']
                type: str
                description: AC SNMP engineID string
            trap_high_cpu_threshold:
                aliases: ['trap-high-cpu-threshold']
                type: int
                description: CPU usage when trap is sent.
            trap_high_mem_threshold:
                aliases: ['trap-high-mem-threshold']
                type: int
                description: Memory usage when trap is sent.
            user:
                type: list
                elements: dict
                description: User.
                suboptions:
                    auth_proto:
                        aliases: ['auth-proto']
                        type: str
                        description: Authentication protocol.
                        choices:
                            - 'md5'
                            - 'sha'
                    auth_pwd:
                        aliases: ['auth-pwd']
                        type: list
                        elements: str
                        description: Password for authentication protocol.
                    name:
                        type: str
                        description: SNMP user name.
                    notify_hosts:
                        aliases: ['notify-hosts']
                        type: list
                        elements: str
                        description: Configure SNMP User Notify Hosts.
                    priv_proto:
                        aliases: ['priv-proto']
                        type: str
                        description: Privacy
                        choices:
                            - 'aes'
                            - 'des'
                            - 'aes256'
                            - 'aes256cisco'
                    priv_pwd:
                        aliases: ['priv-pwd']
                        type: list
                        elements: str
                        description: Password for privacy
                    queries:
                        type: str
                        description: Enable/disable SNMP queries for this user.
                        choices:
                            - 'disable'
                            - 'enable'
                    security_level:
                        aliases: ['security-level']
                        type: str
                        description: Security level for message authentication and encryption.
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
                    status:
                        type: str
                        description: SNMP user enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_status:
                        aliases: ['trap-status']
                        type: str
                        description: Enable/disable traps for this SNMP user.
                        choices:
                            - 'disable'
                            - 'enable'
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
    - name: Configure SNMP.
      fortinet.fmgdevice.fmgd_wireless_snmp:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        wireless_snmp:
          # community:
          #   - hosts:
          #       - id: <integer>
          #         ip: <string>
          #     id: <integer>
          #     name: <string>
          #     query_v1_status: <value in [disable, enable]>
          #     query_v2c_status: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          #     trap_v1_status: <value in [disable, enable]>
          #     trap_v2c_status: <value in [disable, enable]>
          # contact_info: <string>
          # engine_id: <string>
          # trap_high_cpu_threshold: <integer>
          # trap_high_mem_threshold: <integer>
          # user:
          #   - auth_proto: <value in [md5, sha]>
          #     auth_pwd: <list or string>
          #     name: <string>
          #     notify_hosts: <list or string>
          #     priv_proto: <value in [aes, des, aes256, ...]>
          #     priv_pwd: <list or string>
          #     queries: <value in [disable, enable]>
          #     security_level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
          #     status: <value in [disable, enable]>
          #     trap_status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_snmp': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'community': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'hosts': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'query-v1-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'query-v2c-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v1-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v2c-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'contact-info': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'engine-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'trap-high-cpu-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'trap-high-mem-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'user': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-proto': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['md5', 'sha'], 'type': 'str'},
                        'auth-pwd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'notify-hosts': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'priv-proto': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['aes', 'des', 'aes256', 'aes256cisco'], 'type': 'str'},
                        'priv-pwd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'queries': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'security-level': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_snmp'),
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
