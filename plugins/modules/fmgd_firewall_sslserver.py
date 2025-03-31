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
module: fmgd_firewall_sslserver
short_description: Configure SSL servers.
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
    firewall_sslserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_header_x_forwarded_proto:
                aliases: ['add-header-x-forwarded-proto']
                type: str
                description: Enable/disable adding an X-Forwarded-Proto header to forwarded requests.
                choices:
                    - 'disable'
                    - 'enable'
            ip:
                type: str
                description: IPv4 address of the SSL server.
            mapped_port:
                aliases: ['mapped-port']
                type: int
                description: Mapped server service port
            name:
                type: str
                description: Server name.
                required: true
            port:
                type: int
                description: Server service port
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Relative strength of encryption algorithms accepted in negotiation.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_cert:
                aliases: ['ssl-cert']
                type: list
                elements: str
                description: List of certificate names to use for SSL connections to this server.
            ssl_client_renegotiation:
                aliases: ['ssl-client-renegotiation']
                type: str
                description: Allow or block client renegotiation by server.
                choices:
                    - 'deny'
                    - 'allow'
                    - 'secure'
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Bit-size of Diffie-Hellman
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Highest SSL/TLS version to negotiate.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Lowest SSL/TLS version to negotiate.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                aliases: ['ssl-mode']
                type: str
                description: SSL/TLS mode for encryption and decryption of traffic.
                choices:
                    - 'half'
                    - 'full'
            ssl_send_empty_frags:
                aliases: ['ssl-send-empty-frags']
                type: str
                description: Enable/disable sending empty fragments to avoid attack on CBC IV.
                choices:
                    - 'disable'
                    - 'enable'
            url_rewrite:
                aliases: ['url-rewrite']
                type: str
                description: Enable/disable rewriting the URL.
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
    - name: Configure SSL servers.
      fortinet.fmgdevice.fmgd_firewall_sslserver:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_sslserver:
          name: "your value" # Required variable, string
          # add_header_x_forwarded_proto: <value in [disable, enable]>
          # ip: <string>
          # mapped_port: <integer>
          # port: <integer>
          # ssl_algorithm: <value in [high, medium, low]>
          # ssl_cert: <list or string>
          # ssl_client_renegotiation: <value in [deny, allow, secure]>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_mode: <value in [half, full]>
          # ssl_send_empty_frags: <value in [disable, enable]>
          # url_rewrite: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-server'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_sslserver': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'add-header-x-forwarded-proto': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mapped-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ssl-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ssl-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-client-renegotiation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow', 'secure'], 'type': 'str'},
                'ssl-dh-bits': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'ssl-max-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-min-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['half', 'full'], 'type': 'str'},
                'ssl-send-empty-frags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-rewrite': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslserver'),
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
