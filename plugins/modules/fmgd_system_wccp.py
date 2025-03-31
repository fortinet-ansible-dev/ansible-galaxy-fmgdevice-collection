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
module: fmgd_system_wccp
short_description: Configure WCCP.
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
    system_wccp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            assignment_bucket_format:
                aliases: ['assignment-bucket-format']
                type: str
                description: Assignment bucket format for the WCCP cache engine.
                choices:
                    - 'cisco-implementation'
                    - 'wccp-v2'
            assignment_dstaddr_mask:
                aliases: ['assignment-dstaddr-mask']
                type: str
                description: Assignment destination address mask.
            assignment_method:
                aliases: ['assignment-method']
                type: str
                description: Hash key assignment preference.
                choices:
                    - 'HASH'
                    - 'MASK'
                    - 'any'
            assignment_srcaddr_mask:
                aliases: ['assignment-srcaddr-mask']
                type: str
                description: Assignment source address mask.
            assignment_weight:
                aliases: ['assignment-weight']
                type: int
                description: Assignment of hash weight/ratio for the WCCP cache engine.
            authentication:
                type: str
                description: Enable/disable MD5 authentication.
                choices:
                    - 'disable'
                    - 'enable'
            cache_engine_method:
                aliases: ['cache-engine-method']
                type: str
                description: Method used to forward traffic to the routers or to return to the cache engine.
                choices:
                    - 'GRE'
                    - 'L2'
            cache_id:
                aliases: ['cache-id']
                type: str
                description: IP address known to all routers.
            forward_method:
                aliases: ['forward-method']
                type: str
                description: Method used to forward traffic to the cache servers.
                choices:
                    - 'GRE'
                    - 'L2'
                    - 'any'
            group_address:
                aliases: ['group-address']
                type: str
                description: IP multicast address used by the cache routers.
            password:
                type: list
                elements: str
                description: Password for MD5 authentication.
            ports:
                type: list
                elements: int
                description: Service ports.
            ports_defined:
                aliases: ['ports-defined']
                type: str
                description: Match method.
                choices:
                    - 'source'
                    - 'destination'
            primary_hash:
                aliases: ['primary-hash']
                type: list
                elements: str
                description: Hash method.
                choices:
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-port'
                    - 'dst-port'
                    - 'ports-defined'
                    - 'ports-source'
            priority:
                type: int
                description: Service priority.
            protocol:
                type: int
                description: Service protocol.
            return_method:
                aliases: ['return-method']
                type: str
                description: Method used to decline a redirected packet and return it to the FortiGate unit.
                choices:
                    - 'GRE'
                    - 'L2'
                    - 'any'
            router_id:
                aliases: ['router-id']
                type: str
                description: IP address known to all cache engines.
            router_list:
                aliases: ['router-list']
                type: list
                elements: str
                description: IP addresses of one or more WCCP routers.
            server_list:
                aliases: ['server-list']
                type: list
                elements: str
                description: IP addresses and netmasks for up to four cache servers.
            server_type:
                aliases: ['server-type']
                type: str
                description: Cache server type.
                choices:
                    - 'forward'
                    - 'proxy'
            service_id:
                aliases: ['service-id']
                type: str
                description: Service ID.
            service_type:
                aliases: ['service-type']
                type: str
                description: WCCP service type used by the cache server for logical interception and redirection of traffic.
                choices:
                    - 'standard'
                    - 'dynamic'
                    - 'auto'
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
    - name: Configure WCCP.
      fortinet.fmgdevice.fmgd_system_wccp:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_wccp:
          service_id: "your value" # Required variable, string
          # assignment_bucket_format: <value in [cisco-implementation, wccp-v2]>
          # assignment_dstaddr_mask: <string>
          # assignment_method: <value in [HASH, MASK, any]>
          # assignment_srcaddr_mask: <string>
          # assignment_weight: <integer>
          # authentication: <value in [disable, enable]>
          # cache_engine_method: <value in [GRE, L2]>
          # cache_id: <string>
          # forward_method: <value in [GRE, L2, any]>
          # group_address: <string>
          # password: <list or string>
          # ports: <list or integer>
          # ports_defined: <value in [source, destination]>
          # primary_hash:
          #   - "src-ip"
          #   - "dst-ip"
          #   - "src-port"
          #   - "dst-port"
          #   - "ports-defined"
          #   - "ports-source"
          # priority: <integer>
          # protocol: <integer>
          # return_method: <value in [GRE, L2, any]>
          # router_id: <string>
          # router_list: <list or string>
          # server_list: <list or string>
          # server_type: <value in [forward, proxy]>
          # service_type: <value in [standard, dynamic, auto]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/wccp'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'service_id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_wccp': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'assignment-bucket-format': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['cisco-implementation', 'wccp-v2'],
                    'type': 'str'
                },
                'assignment-dstaddr-mask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'assignment-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['HASH', 'MASK', 'any'], 'type': 'str'},
                'assignment-srcaddr-mask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'assignment-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-engine-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['GRE', 'L2'], 'type': 'str'},
                'cache-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'forward-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['GRE', 'L2', 'any'], 'type': 'str'},
                'group-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ports': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'ports-defined': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['source', 'destination'], 'type': 'str'},
                'primary-hash': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ports-defined', 'ports-source'],
                    'elements': 'str'
                },
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'return-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['GRE', 'L2', 'any'], 'type': 'str'},
                'router-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'router-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['forward', 'proxy'], 'type': 'str'},
                'service-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'service-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['standard', 'dynamic', 'auto'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_wccp'),
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
