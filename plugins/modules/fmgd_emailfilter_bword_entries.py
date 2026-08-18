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
module: fmgd_emailfilter_bword_entries
short_description: Spam filter banned word.
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
  bword:
    description: The parameter (bword) in requested url.
    type: str
    required: true
  emailfilter_bword_entries:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Mark spam or good.
        choices: ['spam', 'clear']
      id:
        type: int
        description: Banned word entry ID.
        required: true
      language:
        type: str
        description: Language for the banned word.
        choices: ['western', 'simch', 'trach', 'japanese', 'korean', 'french', 'thai', 'spanish']
      pattern:
        type: str
        description: Pattern for the banned word.
      pattern_type:
        aliases: ['pattern-type']
        type: str
        description: Wildcard pattern or regular expression.
        choices: ['wildcard', 'regexp']
      score:
        type: int
        description: Score value.
      status:
        type: str
        description: Enable/disable status.
        choices: ['disable', 'enable']
      where:
        type: str
        description: Component of the email to be scanned.
        choices: ['all', 'subject', 'body']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Spam filter banned word.
      fortinet.fmgdevice.fmgd_emailfilter_bword_entries:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        bword: <your own value>
        state: present # <value in [present, absent]>
        emailfilter_bword_entries:
          id: 0 # Required variable, integer
          # action: <value in [spam, clear]>
          # language: <value in [western, simch, trach, ...]>
          # pattern: <string>
          # pattern_type: <value in [wildcard, regexp]>
          # score: <integer>
          # status: <value in [disable, enable]>
          # where: <value in [all, subject, body]>
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
        '/pm/config/device/{device}/vdom/{vdom}/emailfilter/bword/{bword}/entries'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'bword': {'required': True, 'type': 'str'},
        'emailfilter_bword_entries': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['spam', 'clear'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'language': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['western', 'simch', 'trach', 'japanese', 'korean', 'french', 'thai', 'spanish'],
                    'type': 'str'
                },
                'pattern': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'pattern-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['wildcard', 'regexp'], 'type': 'str'},
                'score': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'where': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['all', 'subject', 'body'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'emailfilter_bword_entries'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
