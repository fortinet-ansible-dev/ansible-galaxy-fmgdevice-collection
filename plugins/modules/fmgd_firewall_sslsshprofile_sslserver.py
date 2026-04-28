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
module: fmgd_firewall_sslsshprofile_sslserver
short_description: SSL server settings used for client certificate request.
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
    ssl-ssh-profile:
        description: Deprecated, please use "ssl_ssh_profile"
        type: str
    ssl_ssh_profile:
        description: The parameter (ssl-ssh-profile) in requested url.
        type: str
    firewall_sslsshprofile_sslserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ftps_client_certificate:
                aliases: ['ftps-client-certificate']
                type: str
                description: Action based on received client certificate during the FTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            https_client_certificate:
                aliases: ['https-client-certificate']
                type: str
                description: Action based on received client certificate during the HTTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            id:
                type: int
                description: SSL server ID.
                required: true
            imaps_client_certificate:
                aliases: ['imaps-client-certificate']
                type: str
                description: Action based on received client certificate during the IMAPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ip:
                type: str
                description: IPv4 address of the SSL server.
            pop3s_client_certificate:
                aliases: ['pop3s-client-certificate']
                type: str
                description: Action based on received client certificate during the POP3S handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            smtps_client_certificate:
                aliases: ['smtps-client-certificate']
                type: str
                description: Action based on received client certificate during the SMTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ssl_other_client_certificate:
                aliases: ['ssl-other-client-certificate']
                type: str
                description: Action based on received client certificate during an SSL protocol handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            smtps_client_cert_request:
                aliases: ['smtps-client-cert-request']
                type: str
                description: Action based on client certificate request during the SMTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            imaps_client_cert_request:
                aliases: ['imaps-client-cert-request']
                type: str
                description: Action based on client certificate request during the IMAPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ssl_other_client_cert_request:
                aliases: ['ssl-other-client-cert-request']
                type: str
                description: Action based on client certificate request during an SSL protocol handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ftps_client_cert_request:
                aliases: ['ftps-client-cert-request']
                type: str
                description: Action based on client certificate request during the FTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            https_client_cert_request:
                aliases: ['https-client-cert-request']
                type: str
                description: Action based on client certificate request during the HTTPS handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            pop3s_client_cert_request:
                aliases: ['pop3s-client-cert-request']
                type: str
                description: Action based on client certificate request during the POP3S handshake.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
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
    - name: SSL server settings used for client certificate request.
      fortinet.fmgdevice.fmgd_firewall_sslsshprofile_sslserver:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        ssl_ssh_profile: <your own value>
        state: present # <value in [present, absent]>
        firewall_sslsshprofile_sslserver:
          id: 0 # Required variable, integer
          # ftps_client_certificate: <value in [bypass, inspect, block]>
          # https_client_certificate: <value in [bypass, inspect, block]>
          # imaps_client_certificate: <value in [bypass, inspect, block]>
          # ip: <string>
          # pop3s_client_certificate: <value in [bypass, inspect, block]>
          # smtps_client_certificate: <value in [bypass, inspect, block]>
          # ssl_other_client_certificate: <value in [bypass, inspect, block]>
          # smtps_client_cert_request: <value in [bypass, inspect, block]>
          # imaps_client_cert_request: <value in [bypass, inspect, block]>
          # ssl_other_client_cert_request: <value in [bypass, inspect, block]>
          # ftps_client_cert_request: <value in [bypass, inspect, block]>
          # https_client_cert_request: <value in [bypass, inspect, block]>
          # pop3s_client_cert_request: <value in [bypass, inspect, block]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server'
    ]
    url_params = ['device', 'vdom', 'ssl-ssh-profile']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ssl-ssh-profile': {'type': 'str', 'api_name': 'ssl_ssh_profile'},
        'ssl_ssh_profile': {'type': 'str'},
        'firewall_sslsshprofile_sslserver': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'ftps-client-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'https-client-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'imaps-client-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'pop3s-client-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'smtps-client-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ssl-other-client-certificate': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['bypass', 'inspect', 'block'],
                    'type': 'str'
                },
                'smtps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'imaps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ssl-other-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ftps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'https-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'pop3s-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_sslserver'),
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
