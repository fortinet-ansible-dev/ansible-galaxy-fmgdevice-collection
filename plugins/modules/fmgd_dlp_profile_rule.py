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
module: fmgd_dlp_profile_rule
short_description: Set up DLP rules for this profile.
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
  profile:
    description: The parameter (profile) in requested url.
    type: str
    required: true
  dlp_profile_rule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Action to take with content that this DLP profile matches.
        choices: ['log-only', 'block', 'quarantine-ip', 'allow']
      archive:
        type: str
        description: Enable/disable DLP archiving.
        choices: ['disable', 'enable']
      expiry:
        type: str
        description: Quarantine duration in days, hours, minutes
      file_size:
        aliases: ['file-size']
        type: int
        description: Match files greater than or equal to this size
      file_type:
        aliases: ['file-type']
        type: list
        elements: str
        description: Select the number of a DLP file pattern table to match.
      filter_by:
        aliases: ['filter-by']
        type: str
        description: Select the type of content to match.
        choices: ['fingerprint', 'sensor', 'encrypted', 'none', 'mip', 'label']
      id:
        type: int
        description: ID.
        required: true
      label:
        type: list
        elements: str
        description: MIP label dictionary.
      match_percentage:
        aliases: ['match-percentage']
        type: int
        description: Percentage of fingerprints in the fingerprint databases designated with the selected sensitivity to match.
      name:
        type: str
        description: Filter name.
      proto:
        type: list
        elements: str
        description: Check messages or files over one or more of these protocols.
        choices: ['smtp', 'pop3', 'imap', 'http-post', 'http-get', 'ftp', 'nntp', 'mapi', 'ssh',
                  'cifs', 'websocket']
      sensitivity:
        type: list
        elements: str
        description: Select a DLP file pattern sensitivity to match.
      sensor:
        type: list
        elements: str
        description: Select DLP sensors.
      severity:
        type: str
        description: Select the severity or threat level that matches this filter.
        choices: ['info', 'low', 'medium', 'high', 'critical']
      type:
        type: str
        description: Select whether to check the content of messages
        choices: ['file', 'message']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Set up DLP rules for this profile.
      fortinet.fmgdevice.fmgd_dlp_profile_rule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        dlp_profile_rule:
          id: 0 # Required variable, integer
          # action: <value in [log-only, block, quarantine-ip, ...]>
          # archive: <value in [disable, enable]>
          # expiry: <string>
          # file_size: <integer>
          # file_type: <list or string>
          # filter_by: <value in [fingerprint, sensor, encrypted, ...]>
          # label: <list or string>
          # match_percentage: <integer>
          # name: <string>
          # proto: ["smtp", "pop3", "imap", "http-post", "http-get", "ftp", "nntp", "mapi", "ssh",
          #         "cifs", "websocket"]
          # sensitivity: <list or string>
          # sensor: <list or string>
          # severity: <value in [info, low, medium, ...]>
          # type: <value in [file, message]>
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
        '/pm/config/device/{device}/vdom/{vdom}/dlp/profile/{profile}/rule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'dlp_profile_rule': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['log-only', 'block', 'quarantine-ip', 'allow'], 'type': 'str'},
                'archive': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'file-size': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'file-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'filter-by': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['fingerprint', 'sensor', 'encrypted', 'none', 'mip', 'label'],
                    'type': 'str'
                },
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'label': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'match-percentage': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'proto': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['smtp', 'pop3', 'imap', 'http-post', 'http-get', 'ftp', 'nntp', 'mapi', 'ssh', 'cifs', 'websocket'],
                    'elements': 'str'
                },
                'sensitivity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'severity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['info', 'low', 'medium', 'high', 'critical'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['file', 'message'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_profile_rule'),
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
