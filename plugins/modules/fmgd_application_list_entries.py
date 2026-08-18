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
module: fmgd_application_list_entries
short_description: Application list entries.
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
  list:
    description: The parameter (list) in requested url.
    type: str
    required: true
  application_list_entries:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Pass or block traffic, or reset connection for traffic from this application.
        choices: ['pass', 'block', 'reset']
      application:
        type: list
        elements: int
        description: ID of allowed applications.
      behavior:
        type: list
        elements: str
        description: Application behavior filter.
      category:
        type: list
        elements: str
        description: Category ID list.
      exclusion:
        type: list
        elements: int
        description: ID of excluded applications.
      id:
        type: int
        description: Entry ID.
        required: true
      log:
        type: str
        description: Enable/disable logging for this application list.
        choices: ['disable', 'enable']
      log_packet:
        aliases: ['log-packet']
        type: str
        description: Enable/disable packet logging.
        choices: ['disable', 'enable']
      parameters:
        type: list
        elements: dict
        description: Parameters.
        suboptions:
          id:
            type: int
            description: Parameter tuple ID.
          members:
            type: list
            elements: dict
            description: Members.
            suboptions:
              id:
                type: int
                description: Parameter.
              name:
                type: str
                description: Parameter name.
              value:
                type: str
                description: Parameter value.
          value:
            type: str
            description: Parameter value.
      popularity:
        type: list
        elements: str
        description: Application popularity filter
        choices: ['1', '2', '3', '4', '5']
      protocols:
        type: list
        elements: str
        description: Application protocol filter.
      quarantine:
        type: str
        description: Quarantine method.
        choices: ['none', 'attacker']
      quarantine_expiry:
        aliases: ['quarantine-expiry']
        type: str
        description: Duration of quarantine.
      quarantine_log:
        aliases: ['quarantine-log']
        type: str
        description: Enable/disable quarantine logging.
        choices: ['disable', 'enable']
      rate_count:
        aliases: ['rate-count']
        type: int
        description: Count of the rate.
      rate_duration:
        aliases: ['rate-duration']
        type: int
        description: Duration
      rate_mode:
        aliases: ['rate-mode']
        type: str
        description: Rate limit mode.
        choices: ['periodical', 'continuous']
      rate_track:
        aliases: ['rate-track']
        type: str
        description: Track the packet protocol field.
        choices: ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain']
      risk:
        type: list
        elements: int
        description: Risk, or impact, of allowing traffic from this application to occur
      session_ttl:
        aliases: ['session-ttl']
        type: int
        description: Session TTL
      shaper:
        type: list
        elements: str
        description: Traffic shaper.
      technology:
        type: list
        elements: str
        description: Application technology filter.
      vendor:
        type: list
        elements: str
        description: Application vendor filter.
      shaper_reverse:
        aliases: ['shaper-reverse']
        type: list
        elements: str
        description: Reverse traffic shaper.
      per_ip_shaper:
        aliases: ['per-ip-shaper']
        type: list
        elements: str
        description: Per-IP traffic shaper.
      sub_category:
        aliases: ['sub-category']
        type: list
        elements: int
        description: Application Sub-category ID list.
      tags:
        type: list
        elements: str
        description: Tag filter.
      classification:
        type: str
        description: Application classification filter.
        choices: ['none', 'sanctioned', 'unsanctioned', 'unclassified']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Application list entries.
      fortinet.fmgdevice.fmgd_application_list_entries:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        list: <your own value>
        state: present # <value in [present, absent]>
        application_list_entries:
          id: 0 # Required variable, integer
          # action: <value in [pass, block, reset]>
          # application: <list or integer>
          # behavior: <list or string>
          # category: <list or string>
          # exclusion: <list or integer>
          # log: <value in [disable, enable]>
          # log_packet: <value in [disable, enable]>
          # parameters:
          #   - id: <integer>
          #     members:
          #       - id: <integer>
          #         name: <string>
          #         value: <string>
          #     value: <string>
          # popularity: ["1", "2", "3", "4", "5"]
          # protocols: <list or string>
          # quarantine: <value in [none, attacker]>
          # quarantine_expiry: <string>
          # quarantine_log: <value in [disable, enable]>
          # rate_count: <integer>
          # rate_duration: <integer>
          # rate_mode: <value in [periodical, continuous]>
          # rate_track: <value in [none, src-ip, dest-ip, ...]>
          # risk: <list or integer>
          # session_ttl: <integer>
          # shaper: <list or string>
          # technology: <list or string>
          # vendor: <list or string>
          # shaper_reverse: <list or string>
          # per_ip_shaper: <list or string>
          # sub_category: <list or integer>
          # tags: <list or string>
          # classification: <value in [none, sanctioned, unsanctioned, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}/entries'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'list': {'required': True, 'type': 'str'},
        'application_list_entries': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['pass', 'block', 'reset'], 'type': 'str'},
                'application': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'behavior': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'exclusion': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-packet': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'parameters': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'members': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'value': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'value': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'popularity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'choices': ['1', '2', '3', '4', '5'], 'elements': 'str'},
                'protocols': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'attacker'], 'type': 'str'},
                'quarantine-expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'quarantine-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-count': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'rate-duration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'rate-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['periodical', 'continuous'], 'type': 'str'},
                'rate-track': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'],
                    'type': 'str'
                },
                'risk': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'session-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'shaper': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'technology': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vendor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'shaper-reverse': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'per-ip-shaper': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sub-category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'list', 'elements': 'int'},
                'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'classification': {'v_range': [['8.0.0', '']], 'choices': ['none', 'sanctioned', 'unsanctioned', 'unclassified'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_list_entries'),
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
