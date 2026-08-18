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
module: fmgd_wireless_setting
short_description: VDOM wireless controller configuration.
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
  wireless_setting:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      account_id:
        aliases: ['account-id']
        type: str
        description: FortiCloud customer account ID.
      country:
        type: str
        description: Country or region in which the FortiGate is located.
        choices: ['AL', 'DZ', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BZ', 'BO',
                  'BA', 'BR', 'BN', 'BG', 'CA', 'CL', 'CN', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK',
                  'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GE', 'DE', 'GR', 'GT', 'HN', 'HK',
                  'HU', 'IS', 'IN', 'ID', 'IR', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE',
                  'KP', 'KR', 'KW', 'LV', 'LB', 'LI', 'LT', 'LU', 'MO', 'MK', 'MY', 'MT', 'MX',
                  'MC', 'MA', 'NP', 'NL', 'AN', 'NZ', 'NO', 'OM', 'PK', 'PA', 'PG', 'PE', 'PH',
                  'PL', 'PT', 'PR', 'QA', 'RO', 'RU', 'SA', 'CS', 'SG', 'SK', 'SI', 'ZA', 'ES',
                  'LK', 'SE', 'CH', 'SY', 'TW', 'TH', 'TT', 'TN', 'TR', 'AE', 'UA', 'GB', 'US',
                  'PS', 'UY', 'UZ', 'VE', 'VN', 'YE', 'ZW', 'NA', 'BS', 'VC', 'KH', 'MV', 'AF',
                  'NG', 'TZ', 'ZM', 'SN', 'CI', 'GH', 'SD', 'CM', 'MW', 'AO', 'GA', 'ML', 'BJ',
                  'MG', 'TD', 'BW', 'LY', 'RW', 'MZ', 'GM', 'LS', 'MU', 'CG', 'UG', 'BF', 'SL',
                  'SO', 'CD', 'NE', 'CF', 'SZ', 'TG', 'LR', 'MR', 'DJ', 'RE', 'RS', 'ME', 'IQ',
                  'MD', 'KY', 'BB', 'BM', 'TC', 'VI', 'PM', 'MF', 'GD', 'IM', 'FO', 'GI', 'GL',
                  'TM', 'MN', 'VU', 'FJ', 'LA', 'GU', 'WF', 'MH', 'BT', 'FM', 'PF', 'NI', 'PY',
                  'HT', 'GY', 'AW', 'KN', 'GF', 'AS', 'MP', 'PW', 'MM', 'LC', 'GP', 'ET', 'SR',
                  'ZB', 'CX', 'DM', 'MQ', 'YT', 'BL', '--', 'TL']
      darrp_optimize:
        aliases: ['darrp-optimize']
        type: int
        description: Time for running Distributed Automatic Radio Resource Provisioning
      darrp_optimize_schedules:
        aliases: ['darrp-optimize-schedules']
        type: list
        elements: str
        description: Firewall schedules for DARRP running time.
      device_holdoff:
        aliases: ['device-holdoff']
        type: int
        description: Lower limit of creation time of device for identification in minutes
      device_idle:
        aliases: ['device-idle']
        type: int
        description: Upper limit of idle time of device for identification in minutes
      device_weight:
        aliases: ['device-weight']
        type: int
        description: Upper limit of confidence of device for identification
      duplicate_ssid:
        aliases: ['duplicate-ssid']
        type: str
        description: Enable/disable allowing Virtual Access Points
        choices: ['disable', 'enable']
      fake_ssid_action:
        aliases: ['fake-ssid-action']
        type: list
        elements: str
        description: Actions taken for detected fake SSID.
        choices: ['log', 'suppress']
      fapc_compatibility:
        aliases: ['fapc-compatibility']
        type: str
        description: Enable/disable FAP-C series compatibility.
        choices: ['disable', 'enable']
      firmware_provision_on_authorization:
        aliases: ['firmware-provision-on-authorization']
        type: str
        description: Enable/disable automatic provisioning of latest firmware on authorization.
        choices: ['disable', 'enable']
      offending_ssid:
        aliases: ['offending-ssid']
        type: list
        elements: dict
        description: Offending ssid.
        suboptions:
          action:
            type: list
            elements: str
            description: Actions taken for detected offending SSID.
            choices: ['log', 'suppress']
          id:
            type: int
            description: ID.
          ssid_pattern:
            aliases: ['ssid-pattern']
            type: str
            description: Define offending SSID pattern
      phishing_ssid_detect:
        aliases: ['phishing-ssid-detect']
        type: str
        description: Enable/disable phishing SSID detection.
        choices: ['disable', 'enable']
      rolling_wtp_upgrade:
        aliases: ['rolling-wtp-upgrade']
        type: str
        description: Enable/disable rolling WTP upgrade
        choices: ['disable', 'enable']
      wfa_compatibility:
        aliases: ['wfa-compatibility']
        type: str
        description: Enable/disable WFA compatibility.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: VDOM wireless controller configuration.
      fortinet.fmgdevice.fmgd_wireless_setting:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        wireless_setting:
          # account_id: <string>
          # country: <value in [AL, DZ, AR, ...]>
          # darrp_optimize: <integer>
          # darrp_optimize_schedules: <list or string>
          # device_holdoff: <integer>
          # device_idle: <integer>
          # device_weight: <integer>
          # duplicate_ssid: <value in [disable, enable]>
          # fake_ssid_action: ["log", "suppress"]
          # fapc_compatibility: <value in [disable, enable]>
          # firmware_provision_on_authorization: <value in [disable, enable]>
          # offending_ssid:
          #   - action: ["log", "suppress"]
          #     id: <integer>
          #     ssid_pattern: <string>
          # phishing_ssid_detect: <value in [disable, enable]>
          # rolling_wtp_upgrade: <value in [disable, enable]>
          # wfa_compatibility: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_setting': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'account-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'country': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'AL', 'DZ', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BZ', 'BO', 'BA', 'BR', 'BN', 'BG', 'CA', 'CL', 'CN', 'CO',
                        'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GE', 'DE', 'GR', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN',
                        'ID', 'IR', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KP', 'KR', 'KW', 'LV', 'LB', 'LI', 'LT', 'LU', 'MO', 'MK', 'MY',
                        'MT', 'MX', 'MC', 'MA', 'NP', 'NL', 'AN', 'NZ', 'NO', 'OM', 'PK', 'PA', 'PG', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RO', 'RU',
                        'SA', 'CS', 'SG', 'SK', 'SI', 'ZA', 'ES', 'LK', 'SE', 'CH', 'SY', 'TW', 'TH', 'TT', 'TN', 'TR', 'AE', 'UA', 'GB', 'US', 'PS',
                        'UY', 'UZ', 'VE', 'VN', 'YE', 'ZW', 'NA', 'BS', 'VC', 'KH', 'MV', 'AF', 'NG', 'TZ', 'ZM', 'SN', 'CI', 'GH', 'SD', 'CM', 'MW',
                        'AO', 'GA', 'ML', 'BJ', 'MG', 'TD', 'BW', 'LY', 'RW', 'MZ', 'GM', 'LS', 'MU', 'CG', 'UG', 'BF', 'SL', 'SO', 'CD', 'NE', 'CF',
                        'SZ', 'TG', 'LR', 'MR', 'DJ', 'RE', 'RS', 'ME', 'IQ', 'MD', 'KY', 'BB', 'BM', 'TC', 'VI', 'PM', 'MF', 'GD', 'IM', 'FO', 'GI',
                        'GL', 'TM', 'MN', 'VU', 'FJ', 'LA', 'GU', 'WF', 'MH', 'BT', 'FM', 'PF', 'NI', 'PY', 'HT', 'GY', 'AW', 'KN', 'GF', 'AS', 'MP',
                        'PW', 'MM', 'LC', 'GP', 'ET', 'SR', 'ZB', 'CX', 'DM', 'MQ', 'YT', 'BL', '--', 'TL'
                    ],
                    'type': 'str'
                },
                'darrp-optimize': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'darrp-optimize-schedules': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'device-holdoff': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'device-idle': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'device-weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'duplicate-ssid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fake-ssid-action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'choices': ['log', 'suppress'], 'elements': 'str'},
                'fapc-compatibility': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firmware-provision-on-authorization': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'offending-ssid': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'choices': ['log', 'suppress'], 'elements': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ssid-pattern': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'phishing-ssid-detect': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rolling-wtp-upgrade': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wfa-compatibility': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_setting'),
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
