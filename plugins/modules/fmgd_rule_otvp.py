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
module: fmgd_rule_otvp
short_description: Show OT patch signatures.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  rule_otvp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Action.
        choices: ['pass', 'block']
      application:
        type: str
        description: Application.
      date:
        type: int
        description: Date.
      group:
        type: str
        description: Group.
      location:
        type: str
        description: Location.
      log:
        type: str
        description: Log.
        choices: ['disable', 'enable']
      log_packet:
        aliases: ['log-packet']
        type: str
        description: Log packet.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Rule name.
      os:
        type: str
        description: Os.
      rev:
        type: int
        description: Rev.
      rule_id:
        aliases: ['rule-id']
        type: int
        description: Rule id.
      service:
        type: str
        description: Service.
      severity:
        type: str
        description: Severity.
      status:
        type: str
        description: Status.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Show OT patch signatures.
      fortinet.fmgdevice.fmgd_rule_otvp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        rule_otvp:
          # action: <value in [pass, block]>
          # application: <string>
          # date: <integer>
          # group: <string>
          # location: <string>
          # log: <value in [disable, enable]>
          # log_packet: <value in [disable, enable]>
          # name: <string>
          # os: <string>
          # rev: <integer>
          # rule_id: <integer>
          # service: <string>
          # severity: <string>
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
        '/pm/config/device/{device}/global/rule/otvp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'rule_otvp': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'action': {'v_range': [['7.4.3', '']], 'choices': ['pass', 'block'], 'type': 'str'},
                'application': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'date': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'group': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'location': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'log': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-packet': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'os': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rev': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'rule-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'service': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'severity': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'rule_otvp'),
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
