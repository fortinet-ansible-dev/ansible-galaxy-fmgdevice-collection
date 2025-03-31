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
module: fmgd_router_isis_isisinterface
short_description: IS-IS interface configuration.
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    router_isis_isisinterface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_keychain_l1:
                aliases: ['auth-keychain-l1']
                type: list
                elements: str
                description: Authentication key-chain for level 1 PDUs.
            auth_keychain_l2:
                aliases: ['auth-keychain-l2']
                type: list
                elements: str
                description: Authentication key-chain for level 2 PDUs.
            auth_mode_l1:
                aliases: ['auth-mode-l1']
                type: str
                description: Level 1 authentication mode.
                choices:
                    - 'md5'
                    - 'password'
            auth_mode_l2:
                aliases: ['auth-mode-l2']
                type: str
                description: Level 2 authentication mode.
                choices:
                    - 'md5'
                    - 'password'
            auth_password_l1:
                aliases: ['auth-password-l1']
                type: list
                elements: str
                description: Authentication password for level 1 PDUs.
            auth_password_l2:
                aliases: ['auth-password-l2']
                type: list
                elements: str
                description: Authentication password for level 2 PDUs.
            auth_send_only_l1:
                aliases: ['auth-send-only-l1']
                type: str
                description: Enable/disable authentication send-only for level 1 PDUs.
                choices:
                    - 'disable'
                    - 'enable'
            auth_send_only_l2:
                aliases: ['auth-send-only-l2']
                type: str
                description: Enable/disable authentication send-only for level 2 PDUs.
                choices:
                    - 'disable'
                    - 'enable'
            circuit_type:
                aliases: ['circuit-type']
                type: str
                description: IS-IS interfaces circuit type.
                choices:
                    - 'level-1-2'
                    - 'level-1'
                    - 'level-2'
            csnp_interval_l1:
                aliases: ['csnp-interval-l1']
                type: int
                description: Level 1 CSNP interval.
            csnp_interval_l2:
                aliases: ['csnp-interval-l2']
                type: int
                description: Level 2 CSNP interval.
            hello_interval_l1:
                aliases: ['hello-interval-l1']
                type: int
                description: Level 1 hello interval.
            hello_interval_l2:
                aliases: ['hello-interval-l2']
                type: int
                description: Level 2 hello interval.
            hello_multiplier_l1:
                aliases: ['hello-multiplier-l1']
                type: int
                description: Level 1 multiplier for Hello holding time.
            hello_multiplier_l2:
                aliases: ['hello-multiplier-l2']
                type: int
                description: Level 2 multiplier for Hello holding time.
            hello_padding:
                aliases: ['hello-padding']
                type: str
                description: Enable/disable padding to IS-IS hello packets.
                choices:
                    - 'disable'
                    - 'enable'
            lsp_interval:
                aliases: ['lsp-interval']
                type: int
                description: LSP transmission interval
            lsp_retransmit_interval:
                aliases: ['lsp-retransmit-interval']
                type: int
                description: LSP retransmission interval
            mesh_group:
                aliases: ['mesh-group']
                type: str
                description: Enable/disable IS-IS mesh group.
                choices:
                    - 'disable'
                    - 'enable'
            mesh_group_id:
                aliases: ['mesh-group-id']
                type: int
                description: Mesh group ID
            metric_l1:
                aliases: ['metric-l1']
                type: int
                description: Level 1 metric for interface.
            metric_l2:
                aliases: ['metric-l2']
                type: int
                description: Level 2 metric for interface.
            name:
                required: true
                type: list
                elements: str
                description: IS-IS interface name.
            network_type:
                aliases: ['network-type']
                type: str
                description: IS-IS interfaces network type.
                choices:
                    - 'broadcast'
                    - 'point-to-point'
                    - 'loopback'
            priority_l1:
                aliases: ['priority-l1']
                type: int
                description: Level 1 priority.
            priority_l2:
                aliases: ['priority-l2']
                type: int
                description: Level 2 priority.
            status:
                type: str
                description: Enable/disable interface for IS-IS.
                choices:
                    - 'disable'
                    - 'enable'
            status6:
                type: str
                description: Enable/disable IPv6 interface for IS-IS.
                choices:
                    - 'disable'
                    - 'enable'
            wide_metric_l1:
                aliases: ['wide-metric-l1']
                type: int
                description: Level 1 wide metric for interface.
            wide_metric_l2:
                aliases: ['wide-metric-l2']
                type: int
                description: Level 2 wide metric for interface.
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
    - name: IS-IS interface configuration.
      fortinet.fmgdevice.fmgd_router_isis_isisinterface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_isis_isisinterface:
          name: # Required variable, list of device
          # auth_keychain_l1: <list or string>
          # auth_keychain_l2: <list or string>
          # auth_mode_l1: <value in [md5, password]>
          # auth_mode_l2: <value in [md5, password]>
          # auth_password_l1: <list or string>
          # auth_password_l2: <list or string>
          # auth_send_only_l1: <value in [disable, enable]>
          # auth_send_only_l2: <value in [disable, enable]>
          # circuit_type: <value in [level-1-2, level-1, level-2]>
          # csnp_interval_l1: <integer>
          # csnp_interval_l2: <integer>
          # hello_interval_l1: <integer>
          # hello_interval_l2: <integer>
          # hello_multiplier_l1: <integer>
          # hello_multiplier_l2: <integer>
          # hello_padding: <value in [disable, enable]>
          # lsp_interval: <integer>
          # lsp_retransmit_interval: <integer>
          # mesh_group: <value in [disable, enable]>
          # mesh_group_id: <integer>
          # metric_l1: <integer>
          # metric_l2: <integer>
          # network_type: <value in [broadcast, point-to-point, loopback]>
          # priority_l1: <integer>
          # priority_l2: <integer>
          # status: <value in [disable, enable]>
          # status6: <value in [disable, enable]>
          # wide_metric_l1: <integer>
          # wide_metric_l2: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_isis_isisinterface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auth-keychain-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'auth-keychain-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'auth-mode-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['md5', 'password'], 'type': 'str'},
                'auth-mode-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['md5', 'password'], 'type': 'str'},
                'auth-password-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'auth-password-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'auth-send-only-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-send-only-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'circuit-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['level-1-2', 'level-1', 'level-2'], 'type': 'str'},
                'csnp-interval-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'csnp-interval-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-multiplier-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-multiplier-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-padding': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lsp-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'lsp-retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mesh-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mesh-group-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'metric-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'metric-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'list', 'elements': 'str'},
                'network-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['broadcast', 'point-to-point', 'loopback'], 'type': 'str'},
                'priority-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'priority-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wide-metric-l1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wide-metric-l2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_isis_isisinterface'),
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
