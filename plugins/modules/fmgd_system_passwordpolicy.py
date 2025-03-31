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
module: fmgd_system_passwordpolicy
short_description: Configure password policy for locally defined administrator passwords and IPsec VPN pre-shared keys.
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
    system_passwordpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            apply_to:
                aliases: ['apply-to']
                type: list
                elements: str
                description: Apply password policy to administrator passwords or IPsec pre-shared keys or both.
                choices:
                    - 'admin-password'
                    - 'ipsec-preshared-key'
            expire_day:
                aliases: ['expire-day']
                type: int
                description: Number of days after which passwords expire
            expire_status:
                aliases: ['expire-status']
                type: str
                description: Enable/disable password expiration.
                choices:
                    - 'disable'
                    - 'enable'
            min_change_characters:
                aliases: ['min-change-characters']
                type: int
                description: Minimum number of unique characters in new password which do not exist in old password
            min_lower_case_letter:
                aliases: ['min-lower-case-letter']
                type: int
                description: Minimum number of lowercase characters in password
            min_non_alphanumeric:
                aliases: ['min-non-alphanumeric']
                type: int
                description: Minimum number of non-alphanumeric characters in password
            min_number:
                aliases: ['min-number']
                type: int
                description: Minimum number of numeric characters in password
            min_upper_case_letter:
                aliases: ['min-upper-case-letter']
                type: int
                description: Minimum number of uppercase characters in password
            minimum_length:
                aliases: ['minimum-length']
                type: int
                description: Minimum password length
            reuse_password:
                aliases: ['reuse-password']
                type: str
                description: Enable/disable reuse of password.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable setting a password policy for locally defined administrator passwords and IPsec VPN pre-shared keys.
                choices:
                    - 'disable'
                    - 'enable'
            change_4_characters:
                aliases: ['change-4-characters']
                type: str
                description: Enable/disable changing at least 4 characters for a new password
                choices:
                    - 'disable'
                    - 'enable'
            reuse_password_limit:
                aliases: ['reuse-password-limit']
                type: int
                description: Number of times passwords can be reused
            login_lockout_upon_downgrade:
                aliases: ['login-lockout-upon-downgrade']
                type: str
                description: Enable/disable administrative user login lockout upon downgrade
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
    - name: Configure password policy for locally defined administrator passwords and IPsec VPN pre-shared keys.
      fortinet.fmgdevice.fmgd_system_passwordpolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_passwordpolicy:
          # apply_to:
          #   - "admin-password"
          #   - "ipsec-preshared-key"
          # expire_day: <integer>
          # expire_status: <value in [disable, enable]>
          # min_change_characters: <integer>
          # min_lower_case_letter: <integer>
          # min_non_alphanumeric: <integer>
          # min_number: <integer>
          # min_upper_case_letter: <integer>
          # minimum_length: <integer>
          # reuse_password: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # change_4_characters: <value in [disable, enable]>
          # reuse_password_limit: <integer>
          # login_lockout_upon_downgrade: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/password-policy'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_passwordpolicy': {
            'type': 'dict',
            'no_log': False,
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'apply-to': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['admin-password', 'ipsec-preshared-key'],
                    'elements': 'str'
                },
                'expire-day': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'expire-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'min-change-characters': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'min-lower-case-letter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'min-non-alphanumeric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'min-number': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'min-upper-case-letter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'minimum-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'reuse-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'change-4-characters': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reuse-password-limit': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'},
                'login-lockout-upon-downgrade': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_passwordpolicy'),
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
