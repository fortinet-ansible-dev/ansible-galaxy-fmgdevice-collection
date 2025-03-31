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
module: fmgd_ftpproxy_explicit
short_description: Configure explicit FTP proxy settings.
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
    ftpproxy_explicit:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            incoming_ip:
                aliases: ['incoming-ip']
                type: str
                description: Accept incoming FTP requests from this IP address.
            incoming_port:
                aliases: ['incoming-port']
                type: list
                elements: str
                description: Accept incoming FTP requests on one or more ports.
            outgoing_ip:
                aliases: ['outgoing-ip']
                type: list
                elements: str
                description: Outgoing FTP requests will leave from this IP address.
            sec_default_action:
                aliases: ['sec-default-action']
                type: str
                description: Accept or deny explicit FTP proxy sessions when no FTP proxy firewall policy exists.
                choices:
                    - 'deny'
                    - 'accept'
            server_data_mode:
                aliases: ['server-data-mode']
                type: str
                description: Determine mode of data session on FTP server side.
                choices:
                    - 'client'
                    - 'passive'
            ssl:
                type: str
                description: Enable/disable the explicit FTPS proxy.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Relative strength of encryption algorithms accepted in negotiation.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
            ssl_cert:
                aliases: ['ssl-cert']
                type: list
                elements: str
                description: List of certificate names to use for SSL connections to this server.
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Bit-size of Diffie-Hellman
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            status:
                type: str
                description: Enable/disable the explicit FTP proxy.
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
    - name: Configure explicit FTP proxy settings.
      fortinet.fmgdevice.fmgd_ftpproxy_explicit:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        ftpproxy_explicit:
          # incoming_ip: <string>
          # incoming_port: <list or string>
          # outgoing_ip: <list or string>
          # sec_default_action: <value in [deny, accept]>
          # server_data_mode: <value in [client, passive]>
          # ssl: <value in [disable, enable]>
          # ssl_algorithm: <value in [high, low, medium]>
          # ssl_cert: <list or string>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/ftp-proxy/explicit'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ftpproxy_explicit': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'incoming-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'incoming-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'outgoing-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sec-default-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'server-data-mode': {'v_range': [['7.4.3', '']], 'choices': ['client', 'passive'], 'type': 'str'},
                'ssl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['high', 'low', 'medium'], 'type': 'str'},
                'ssl-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-dh-bits': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ftpproxy_explicit'),
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
