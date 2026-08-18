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
module: fmgd_system_lldp_networkpolicy
short_description: Configure LLDP network policy.
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
  system_lldp_networkpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comment:
        type: str
        description: Comment.
      guest:
        type: dict
        description: Guest.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      guest_voice_signaling:
        aliases: ['guest-voice-signaling']
        type: dict
        description: Guest voice signaling.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      name:
        type: str
        description: LLDP network policy name.
        required: true
      softphone:
        type: dict
        description: Softphone.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      streaming_video:
        aliases: ['streaming-video']
        type: dict
        description: Streaming video.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      video_conferencing:
        aliases: ['video-conferencing']
        type: dict
        description: Video conferencing.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      video_signaling:
        aliases: ['video-signaling']
        type: dict
        description: Video signaling.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      voice:
        type: dict
        description: Voice.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
      voice_signaling:
        aliases: ['voice-signaling']
        type: dict
        description: Voice signaling.
        suboptions:
          dscp:
            type: int
            description: Differentiated Services Code Point
          priority:
            type: int
            description: '802.'
          status:
            type: str
            description: Enable/disable advertising this policy.
            choices: ['disable', 'enable']
          tag:
            type: str
            description: Advertise tagged or untagged traffic.
            choices: ['none', 'dot1q', 'dot1p']
          vlan:
            type: int
            description: '802.'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LLDP network policy.
      fortinet.fmgdevice.fmgd_system_lldp_networkpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_lldp_networkpolicy:
          name: "your value" # Required variable, string
          # comment: <string>
          # guest:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # guest_voice_signaling:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # softphone:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # streaming_video:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # video_conferencing:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # video_signaling:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # voice:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
          # voice_signaling:
          #   dscp: <integer>
          #   priority: <integer>
          #   status: <value in [disable, enable]>
          #   tag: <value in [none, dot1q, dot1p]>
          #   vlan: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_lldp_networkpolicy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'guest': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'guest-voice-signaling': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'softphone': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'streaming-video': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'video-conferencing': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'video-signaling': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'voice': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'voice-signaling': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_lldp_networkpolicy'),
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
