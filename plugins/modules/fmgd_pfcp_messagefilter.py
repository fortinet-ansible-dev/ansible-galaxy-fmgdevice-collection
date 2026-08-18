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
module: fmgd_pfcp_messagefilter
short_description: Message filter for PFCP messages.
version_added: "1.0.0"
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
  pfcp_messagefilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      association_release:
        aliases: ['association-release']
        type: str
        description: Allow or deny PFCP association release request
        choices: ['deny', 'allow']
      association_setup:
        aliases: ['association-setup']
        type: str
        description: Allow or deny PFCP association setup request
        choices: ['deny', 'allow']
      association_update:
        aliases: ['association-update']
        type: str
        description: Allow or deny PFCP association update request
        choices: ['deny', 'allow']
      heartbeat:
        type: str
        description: Allow or deny PFCP heartbeat request
        choices: ['deny', 'allow']
      name:
        type: str
        description: Message filter name.
        required: true
      node_report:
        aliases: ['node-report']
        type: str
        description: Allow or deny PFCP node report request
        choices: ['deny', 'allow']
      pfd_management:
        aliases: ['pfd-management']
        type: str
        description: Allow or deny PFCP PFD management request
        choices: ['deny', 'allow']
      session_deletion:
        aliases: ['session-deletion']
        type: str
        description: Allow or deny PFCP session deletion request
        choices: ['deny', 'allow']
      session_establish:
        aliases: ['session-establish']
        type: str
        description: Allow or deny PFCP session establishment request
        choices: ['deny', 'allow']
      session_modification:
        aliases: ['session-modification']
        type: str
        description: Allow or deny PFCP session modification request
        choices: ['deny', 'allow']
      session_report:
        aliases: ['session-report']
        type: str
        description: Allow or deny PFCP session report request
        choices: ['deny', 'allow']
      session_set_deletion:
        aliases: ['session-set-deletion']
        type: str
        description: Allow or deny PFCP session set deletion request
        choices: ['deny', 'allow']
      unknown_message:
        aliases: ['unknown-message']
        type: str
        description: Allow or deny unknown messages.
        choices: ['deny', 'allow']
      unknown_message_allow_list:
        aliases: ['unknown-message-allow-list']
        type: list
        elements: int
        description: Allow list of unknown messages.
      version_not_support:
        aliases: ['version-not-support']
        type: str
        description: Allow or deny PFCP version not supported response
        choices: ['deny', 'allow']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Message filter for PFCP messages.
      fortinet.fmgdevice.fmgd_pfcp_messagefilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        pfcp_messagefilter:
          name: "your value" # Required variable, string
          # association_release: <value in [deny, allow]>
          # association_setup: <value in [deny, allow]>
          # association_update: <value in [deny, allow]>
          # heartbeat: <value in [deny, allow]>
          # node_report: <value in [deny, allow]>
          # pfd_management: <value in [deny, allow]>
          # session_deletion: <value in [deny, allow]>
          # session_establish: <value in [deny, allow]>
          # session_modification: <value in [deny, allow]>
          # session_report: <value in [deny, allow]>
          # session_set_deletion: <value in [deny, allow]>
          # unknown_message: <value in [deny, allow]>
          # unknown_message_allow_list: <list or integer>
          # version_not_support: <value in [deny, allow]>
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
        '/pm/config/device/{device}/vdom/{vdom}/pfcp/message-filter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'pfcp_messagefilter': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'association-release': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'association-setup': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'association-update': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'heartbeat': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'node-report': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'pfd-management': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'session-deletion': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'session-establish': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'session-modification': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'session-report': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'session-set-deletion': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'unknown-message': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'unknown-message-allow-list': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'version-not-support': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pfcp_messagefilter'),
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
