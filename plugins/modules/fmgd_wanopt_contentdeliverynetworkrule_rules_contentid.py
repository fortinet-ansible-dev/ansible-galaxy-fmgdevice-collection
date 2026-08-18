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
module: fmgd_wanopt_contentdeliverynetworkrule_rules_contentid
short_description: Content ID settings.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  content-delivery-network-rule:
    description: Deprecated, please use "content_delivery_network_rule"
    type: str
  content_delivery_network_rule:
    description: The parameter (content-delivery-network-rule) in requested url.
    type: str
  rules:
    description: The parameter (rules) in requested url.
    type: str
    required: true
  wanopt_contentdeliverynetworkrule_rules_contentid:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      end_direction:
        aliases: ['end-direction']
        type: str
        description: Search direction from end-str match.
        choices: ['forward', 'backward']
      end_skip:
        aliases: ['end-skip']
        type: int
        description: Number of characters in URL to skip after end-str has been matched.
      end_str:
        aliases: ['end-str']
        type: str
        description: String from which to end search.
      range_str:
        aliases: ['range-str']
        type: str
        description: Name of content ID within the start string and end string.
      start_direction:
        aliases: ['start-direction']
        type: str
        description: Search direction from start-str match.
        choices: ['forward', 'backward']
      start_skip:
        aliases: ['start-skip']
        type: int
        description: Number of characters in URL to skip after start-str has been matched.
      start_str:
        aliases: ['start-str']
        type: str
        description: String from which to start search.
      target:
        type: str
        description: Option in HTTP header or URL parameter to match.
        choices: ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id',
                  'hls-manifest', 'dash-manifest', 'hls-fragment', 'dash-fragment']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Content ID settings.
      fortinet.fmgdevice.fmgd_wanopt_contentdeliverynetworkrule_rules_contentid:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        content_delivery_network_rule: <your own value>
        rules: <your own value>
        wanopt_contentdeliverynetworkrule_rules_contentid:
          # end_direction: <value in [forward, backward]>
          # end_skip: <integer>
          # end_str: <string>
          # range_str: <string>
          # start_direction: <value in [forward, backward]>
          # start_skip: <integer>
          # start_str: <string>
          # target: <value in [path, parameter, referrer, ...]>
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
        '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/content-id'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'content-delivery-network-rule': {'type': 'str', 'api_name': 'content_delivery_network_rule'},
        'content_delivery_network_rule': {'type': 'str'},
        'rules': {'required': True, 'type': 'str'},
        'wanopt_contentdeliverynetworkrule_rules_contentid': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'end-direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['forward', 'backward'], 'type': 'str'},
                'end-skip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'end-str': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'range-str': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'start-direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['forward', 'backward'], 'type': 'str'},
                'start-skip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'start-str': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'target': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id', 'hls-manifest', 'dash-manifest', 'hls-fragment',
                        'dash-fragment'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_contentdeliverynetworkrule_rules_contentid'),
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
