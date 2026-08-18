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
module: fmgd_user_passwordpolicy
short_description: Configure user password policy.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  user_passwordpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      expire_days:
        aliases: ['expire-days']
        type: int
        description: Time in days before the users password expires.
      expired_password_renewal:
        aliases: ['expired-password-renewal']
        type: str
        description: Enable/disable renewal of a password that already is expired.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Password policy name.
        required: true
      warn_days:
        aliases: ['warn-days']
        type: int
        description: Time in days before a password expiration warning message is displayed to the user upon login.
      reuse_password:
        aliases: ['reuse-password']
        type: str
        description: Enable/disable reuse of password.
        choices: ['disable', 'enable']
      min_non_alphanumeric:
        aliases: ['min-non-alphanumeric']
        type: int
        description: Minimum number of non-alphanumeric characters in password
      expire_status:
        aliases: ['expire-status']
        type: str
        description: Enable/disable password expiration.
        choices: ['disable', 'enable']
      min_number:
        aliases: ['min-number']
        type: int
        description: Minimum number of numeric characters in password
      min_upper_case_letter:
        aliases: ['min-upper-case-letter']
        type: int
        description: Minimum number of uppercase characters in password
      min_lower_case_letter:
        aliases: ['min-lower-case-letter']
        type: int
        description: Minimum number of lowercase characters in password
      min_change_characters:
        aliases: ['min-change-characters']
        type: int
        description: Minimum number of unique characters in new password which do not exist in old password
      minimum_length:
        aliases: ['minimum-length']
        type: int
        description: Minimum password length
      reuse_password_limit:
        aliases: ['reuse-password-limit']
        type: int
        description: Number of times passwords can be reused
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure user password policy.
      fortinet.fmgdevice.fmgd_user_passwordpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_passwordpolicy:
          name: "your value" # Required variable, string
          # expire_days: <integer>
          # expired_password_renewal: <value in [disable, enable]>
          # warn_days: <integer>
          # reuse_password: <value in [disable, enable]>
          # min_non_alphanumeric: <integer>
          # expire_status: <value in [disable, enable]>
          # min_number: <integer>
          # min_upper_case_letter: <integer>
          # min_lower_case_letter: <integer>
          # min_change_characters: <integer>
          # minimum_length: <integer>
          # reuse_password_limit: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/password-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_passwordpolicy': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': False,
            'options': {
                'expire-days': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'expired-password-renewal': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'warn-days': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'reuse-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'min-non-alphanumeric': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'expire-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'min-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'min-upper-case-letter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'min-lower-case-letter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'min-change-characters': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'minimum-length': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'reuse-password-limit': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_passwordpolicy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
