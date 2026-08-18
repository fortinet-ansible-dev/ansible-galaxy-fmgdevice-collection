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
module: fmgd_extensioncontroller_extenderprofile_cellular_smsnotification_receiver
short_description: SMS notification receiver list.
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
  extender-profile:
    description: Deprecated, please use "extender_profile"
    type: str
  extender_profile:
    description: The parameter (extender-profile) in requested url.
    type: str
  extensioncontroller_extenderprofile_cellular_smsnotification_receiver:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      alert:
        type: list
        elements: str
        description: Alert multi-options.
        choices: ['system-reboot', 'data-exhausted', 'session-disconnect', 'low-signal-strength',
                  'mode-switch', 'os-image-fallback', 'fgt-backup-mode-switch']
      name:
        type: str
        description: FortiExtender SMS notification receiver name.
        required: true
      phone_number:
        aliases: ['phone-number']
        type: str
        description: Receiver phone number.
      status:
        type: str
        description: SMS notification receiver status.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SMS notification receiver list.
      fortinet.fmgdevice.fmgd_extensioncontroller_extenderprofile_cellular_smsnotification_receiver:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        extender_profile: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extenderprofile_cellular_smsnotification_receiver:
          name: "your value" # Required variable, string
          # alert: ["system-reboot", "data-exhausted", "session-disconnect",
          #         "low-signal-strength", "mode-switch", "os-image-fallback",
          #         "fgt-backup-mode-switch"]
          # phone_number: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'alert': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': [
                        'system-reboot', 'data-exhausted', 'session-disconnect', 'low-signal-strength', 'mode-switch', 'os-image-fallback',
                        'fgt-backup-mode-switch'
                    ],
                    'elements': 'str'
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'phone-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'),
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
