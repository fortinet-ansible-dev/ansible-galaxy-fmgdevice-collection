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
module: fmgd_user_peer
short_description: Configure peer users.
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
    user_peer:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ca:
                type: list
                elements: str
                description: Name of the CA certificate.
            cn:
                type: str
                description: Peer certificate common name.
            cn_type:
                aliases: ['cn-type']
                type: str
                description: Peer certificate common name type.
                choices:
                    - 'string'
                    - 'email'
                    - 'FQDN'
                    - 'ipv4'
                    - 'ipv6'
            ldap_mode:
                aliases: ['ldap-mode']
                type: str
                description: Mode for LDAP peer authentication.
                choices:
                    - 'password'
                    - 'principal-name'
            ldap_password:
                aliases: ['ldap-password']
                type: list
                elements: str
                description: Password for LDAP server bind.
            ldap_server:
                aliases: ['ldap-server']
                type: list
                elements: str
                description: Name of an LDAP server defined under the user ldap command.
            ldap_username:
                aliases: ['ldap-username']
                type: str
                description: Username for LDAP server bind.
            mandatory_ca_verify:
                aliases: ['mandatory-ca-verify']
                type: str
                description: Determine what happens to the peer if the CA certificate is not installed.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Peer name.
                required: true
            ocsp_override_server:
                aliases: ['ocsp-override-server']
                type: list
                elements: str
                description: Online Certificate Status Protocol
            passwd:
                type: list
                elements: str
                description: Peers password used for two-factor authentication.
            subject:
                type: str
                description: Peer certificate name constraints.
            two_factor:
                aliases: ['two-factor']
                type: str
                description: Enable/disable two-factor authentication, applying certificate and password-based authentication.
                choices:
                    - 'disable'
                    - 'enable'
            mfa_mode:
                aliases: ['mfa-mode']
                type: str
                description: MFA mode for remote peer authentication/authorization.
                choices:
                    - 'none'
                    - 'password'
                    - 'subject-identity'
            mfa_server:
                aliases: ['mfa-server']
                type: list
                elements: str
                description: Name of a remote authenticator.
            mfa_password:
                aliases: ['mfa-password']
                type: list
                elements: str
                description: Unified password for remote authentication.
            mfa_username:
                aliases: ['mfa-username']
                type: str
                description: Unified username for remote authentication.
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
    - name: Configure peer users.
      fortinet.fmgdevice.fmgd_user_peer:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_peer:
          name: "your value" # Required variable, string
          # ca: <list or string>
          # cn: <string>
          # cn_type: <value in [string, email, FQDN, ...]>
          # ldap_mode: <value in [password, principal-name]>
          # ldap_password: <list or string>
          # ldap_server: <list or string>
          # ldap_username: <string>
          # mandatory_ca_verify: <value in [disable, enable]>
          # ocsp_override_server: <list or string>
          # passwd: <list or string>
          # subject: <string>
          # two_factor: <value in [disable, enable]>
          # mfa_mode: <value in [none, password, subject-identity]>
          # mfa_server: <list or string>
          # mfa_password: <list or string>
          # mfa_username: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/peer'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_peer': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'ca': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cn-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['string', 'email', 'FQDN', 'ipv4', 'ipv6'], 'type': 'str'},
                'ldap-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['password', 'principal-name'], 'type': 'str'},
                'ldap-password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ldap-username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'mandatory-ca-verify': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'ocsp-override-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'passwd': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'subject': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'two-factor': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mfa-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['none', 'password', 'subject-identity'], 'type': 'str'},
                'mfa-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'mfa-password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'mfa-username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_peer'),
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
