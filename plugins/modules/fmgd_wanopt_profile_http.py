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
module: fmgd_wanopt_profile_http
short_description: Enable/disable HTTP WAN Optimization and configure HTTP WAN Optimization features.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    wanopt_profile_http:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            byte_caching:
                aliases: ['byte-caching']
                type: str
                description: Enable/disable byte-caching.
                choices:
                    - 'disable'
                    - 'enable'
            prefer_chunking:
                aliases: ['prefer-chunking']
                type: str
                description: Select dynamic or fixed-size data chunking for WAN Optimization.
                choices:
                    - 'dynamic'
                    - 'fix'
            protocol_opt:
                aliases: ['protocol-opt']
                type: str
                description: Select protocol specific optimization or generic TCP optimization.
                choices:
                    - 'protocol'
                    - 'tcp'
            secure_tunnel:
                aliases: ['secure-tunnel']
                type: str
                description: Enable/disable securing the WAN Opt tunnel using SSL.
                choices:
                    - 'disable'
                    - 'enable'
            ssl:
                type: str
                description: Enable/disable SSL/TLS offloading
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable WAN Optimization.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_sharing:
                aliases: ['tunnel-sharing']
                type: str
                description: Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                choices:
                    - 'private'
                    - 'shared'
                    - 'express-shared'
            log_traffic:
                aliases: ['log-traffic']
                type: str
                description: Enable/disable logging.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_port:
                aliases: ['ssl-port']
                type: list
                elements: int
                description: Port on which to expect HTTPS traffic for SSL/TLS offloading.
            unknown_http_version:
                aliases: ['unknown-http-version']
                type: str
                description: How to handle HTTP sessions that do not comply with HTTP 0.
                choices:
                    - 'best-effort'
                    - 'reject'
                    - 'tunnel'
            port:
                type: list
                elements: int
                description: Single port number or port number range for HTTP.
            tunnel_non_http:
                aliases: ['tunnel-non-http']
                type: str
                description: Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Enable/disable HTTP WAN Optimization and configure HTTP WAN Optimization features.
      fortinet.fmgdevice.fmgd_wanopt_profile_http:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        wanopt_profile_http:
          # byte_caching: <value in [disable, enable]>
          # prefer_chunking: <value in [dynamic, fix]>
          # protocol_opt: <value in [protocol, tcp]>
          # secure_tunnel: <value in [disable, enable]>
          # ssl: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # tunnel_sharing: <value in [private, shared, express-shared]>
          # log_traffic: <value in [disable, enable]>
          # ssl_port: <list or integer>
          # unknown_http_version: <value in [best-effort, reject, tunnel]>
          # port: <list or integer>
          # tunnel_non_http: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wanopt/profile/{profile}/http'
    ]
    url_params = ['device', 'vdom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'wanopt_profile_http': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'byte-caching': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prefer-chunking': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['dynamic', 'fix'], 'type': 'str'},
                'protocol-opt': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['protocol', 'tcp'], 'type': 'str'},
                'secure-tunnel': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-sharing': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['private', 'shared', 'express-shared'], 'type': 'str'},
                'log-traffic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-port': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'int'},
                'unknown-http-version': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['best-effort', 'reject', 'tunnel'], 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'int'},
                'tunnel-non-http': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_profile_http'),
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
