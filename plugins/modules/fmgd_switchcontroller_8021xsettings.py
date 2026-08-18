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
module: fmgd_switchcontroller_8021xsettings
short_description: Configure global 802.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  switchcontroller_8021xsettings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      link_down_auth:
        aliases: ['link-down-auth']
        type: str
        description: Interface-reauthentication state to set if a link is down.
        choices: ['set-unauth', 'no-action']
      mab_reauth:
        aliases: ['mab-reauth']
        type: str
        description: Enable/disable MAB re-authentication.
        choices: ['disable', 'enable']
      mac_called_station_delimiter:
        aliases: ['mac-called-station-delimiter']
        type: str
        description: MAC called station delimiter
        choices: ['hyphen', 'single-hyphen', 'colon', 'none']
      mac_calling_station_delimiter:
        aliases: ['mac-calling-station-delimiter']
        type: str
        description: MAC calling station delimiter
        choices: ['hyphen', 'single-hyphen', 'colon', 'none']
      mac_case:
        aliases: ['mac-case']
        type: str
        description: MAC case
        choices: ['uppercase', 'lowercase']
      mac_password_delimiter:
        aliases: ['mac-password-delimiter']
        type: str
        description: MAC authentication password delimiter
        choices: ['hyphen', 'single-hyphen', 'colon', 'none']
      mac_username_delimiter:
        aliases: ['mac-username-delimiter']
        type: str
        description: MAC authentication username delimiter
        choices: ['hyphen', 'single-hyphen', 'colon', 'none']
      max_reauth_attempt:
        aliases: ['max-reauth-attempt']
        type: int
        description: Maximum number of authentication attempts
      reauth_period:
        aliases: ['reauth-period']
        type: int
        description: Period of time to allow for reauthentication
      tx_period:
        aliases: ['tx-period']
        type: int
        description: '802.'
      allow_mac_move:
        aliases: ['allow-mac-move']
        type: str
        description: Enable/disable MAC move
        choices: ['disable', 'enable']
      mab_entry_as:
        aliases: ['mab-entry-as']
        type: str
        description: Configure MAB MAC entry as static or dynamic
        choices: ['dynamic', 'static']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure global 802.
      fortinet.fmgdevice.fmgd_switchcontroller_8021xsettings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        switchcontroller_8021xsettings:
          # link_down_auth: <value in [set-unauth, no-action]>
          # mab_reauth: <value in [disable, enable]>
          # mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_case: <value in [uppercase, lowercase]>
          # mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # max_reauth_attempt: <integer>
          # reauth_period: <integer>
          # tx_period: <integer>
          # allow_mac_move: <value in [disable, enable]>
          # mab_entry_as: <value in [dynamic, static]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/802-1X-settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_8021xsettings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'link-down-auth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['set-unauth', 'no-action'], 'type': 'str'},
                'mab-reauth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-called-station-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-calling-station-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-case': {'v_range': [['7.4.3', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-username-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'max-reauth-attempt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'reauth-period': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'tx-period': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'allow-mac-move': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mab-entry-as': {'v_range': [['8.0.0', '']], 'choices': ['dynamic', 'static'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_8021xsettings'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
