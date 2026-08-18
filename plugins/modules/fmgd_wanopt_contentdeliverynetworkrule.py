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
module: fmgd_wanopt_contentdeliverynetworkrule
short_description: Configure WAN optimization content delivery network rules.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  wanopt_contentdeliverynetworkrule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      category:
        type: str
        description: Content delivery network rule category.
        choices: ['vcache', 'youtube']
      comment:
        type: str
        description: Comment about this CDN-rule.
      host_domain_name_suffix:
        aliases: ['host-domain-name-suffix']
        type: list
        elements: str
        description: Suffix portion of the fully qualified domain name.
      name:
        type: str
        description: Name of table.
        required: true
      request_cache_control:
        aliases: ['request-cache-control']
        type: str
        description: Enable/disable HTTP request cache control.
        choices: ['disable', 'enable']
      response_cache_control:
        aliases: ['response-cache-control']
        type: str
        description: Enable/disable HTTP response cache control.
        choices: ['disable', 'enable']
      response_expires:
        aliases: ['response-expires']
        type: str
        description: Enable/disable HTTP response cache expires.
        choices: ['disable', 'enable']
      rules:
        type: list
        elements: dict
        description: Rules.
        suboptions:
          content_id:
            aliases: ['content-id']
            type: dict
            description: Content id.
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
                choices: ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id',
                          'youku-id', 'hls-manifest', 'dash-manifest', 'hls-fragment',
                          'dash-fragment']
          match_entries:
            aliases: ['match-entries']
            type: list
            elements: dict
            description: Match entries.
            suboptions:
              id:
                type: int
                description: Rule ID.
              pattern:
                type: list
                elements: str
                description: Pattern string for matching target
              target:
                type: str
                description: Option in HTTP header or URL parameter to match.
                choices: ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id']
          match_mode:
            aliases: ['match-mode']
            type: str
            description: Match criteria for collecting content ID.
            choices: ['any', 'all']
          name:
            type: str
            description: WAN optimization content delivery network rule name.
          skip_entries:
            aliases: ['skip-entries']
            type: list
            elements: dict
            description: Skip entries.
            suboptions:
              id:
                type: int
                description: Rule ID.
              pattern:
                type: list
                elements: str
                description: Pattern string for matching target
              target:
                type: str
                description: Option in HTTP header or URL parameter to match.
                choices: ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id']
          skip_rule_mode:
            aliases: ['skip-rule-mode']
            type: str
            description: Skip mode when evaluating skip-rules.
            choices: ['any', 'all']
      status:
        type: str
        description: Enable/disable WAN optimization content delivery network rules.
        choices: ['disable', 'enable']
      text_response_vcache:
        aliases: ['text-response-vcache']
        type: str
        description: Enable/disable caching of text responses.
        choices: ['disable', 'enable']
      updateserver:
        type: str
        description: Enable/disable update server.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WAN optimization content delivery network rules.
      fortinet.fmgdevice.fmgd_wanopt_contentdeliverynetworkrule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        wanopt_contentdeliverynetworkrule:
          name: "your value" # Required variable, string
          # category: <value in [vcache, youtube]>
          # comment: <string>
          # host_domain_name_suffix: <list or string>
          # request_cache_control: <value in [disable, enable]>
          # response_cache_control: <value in [disable, enable]>
          # response_expires: <value in [disable, enable]>
          # rules:
          #   - content_id:
          #       end_direction: <value in [forward, backward]>
          #       end_skip: <integer>
          #       end_str: <string>
          #       range_str: <string>
          #       start_direction: <value in [forward, backward]>
          #       start_skip: <integer>
          #       start_str: <string>
          #       target: <value in [path, parameter, referrer, ...]>
          #     match_entries:
          #       - id: <integer>
          #         pattern: <list or string>
          #         target: <value in [path, parameter, referrer, ...]>
          #     match_mode: <value in [any, all]>
          #     name: <string>
          #     skip_entries:
          #       - id: <integer>
          #         pattern: <list or string>
          #         target: <value in [path, parameter, referrer, ...]>
          #     skip_rule_mode: <value in [any, all]>
          # status: <value in [disable, enable]>
          # text_response_vcache: <value in [disable, enable]>
          # updateserver: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'wanopt_contentdeliverynetworkrule': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'category': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['vcache', 'youtube'], 'type': 'str'},
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'host-domain-name-suffix': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'request-cache-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'response-cache-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'response-expires': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rules': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'content-id': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'dict',
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
                                        'path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id', 'hls-manifest', 'dash-manifest',
                                        'hls-fragment', 'dash-fragment'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'match-entries': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'pattern': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'target': {
                                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                                    'choices': ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id'],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'match-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'all'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'skip-entries': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'pattern': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'target': {
                                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                                    'choices': ['path', 'parameter', 'referrer', 'youtube-map', 'youtube-id', 'youku-id'],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'skip-rule-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'all'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'text-response-vcache': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'updateserver': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_contentdeliverynetworkrule'),
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
