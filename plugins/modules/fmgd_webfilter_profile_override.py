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
module: fmgd_webfilter_profile_override
short_description: Web Filter override settings.
version_added: "1.1.0"
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
  profile:
    description: The parameter (profile) in requested url.
    type: str
    required: true
  webfilter_profile_override:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ovrd_cookie:
        aliases: ['ovrd-cookie']
        type: str
        description: Allow/deny browser-based
        choices: ['deny', 'allow']
      ovrd_dur:
        aliases: ['ovrd-dur']
        type: str
        description: Override duration.
      ovrd_dur_mode:
        aliases: ['ovrd-dur-mode']
        type: str
        description: Override duration mode.
        choices: ['constant', 'ask']
      ovrd_scope:
        aliases: ['ovrd-scope']
        type: str
        description: Override scope.
        choices: ['user', 'user-group', 'ip', 'ask', 'browser']
      ovrd_user_group:
        aliases: ['ovrd-user-group']
        type: list
        elements: str
        description: User groups with permission to use the override.
      profile:
        type: list
        elements: str
        description: Web filter profile with permission to create overrides.
      profile_attribute:
        aliases: ['profile-attribute']
        type: str
        description: Profile attribute to retrieve from the RADIUS server.
        choices: ['User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask',
                  'Filter-Id', 'Login-IP-Host', 'Reply-Message', 'Callback-Number', 'Callback-Id',
                  'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id',
                  'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service',
                  'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Zone', 'Acct-Session-Id',
                  'Acct-Multi-Session-Id']
      profile_type:
        aliases: ['profile-type']
        type: str
        description: Override profile type.
        choices: ['list', 'radius']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Web Filter override settings.
      fortinet.fmgdevice.fmgd_webfilter_profile_override:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        webfilter_profile_override:
          # ovrd_cookie: <value in [deny, allow]>
          # ovrd_dur: <string>
          # ovrd_dur_mode: <value in [constant, ask]>
          # ovrd_scope: <value in [user, user-group, ip, ...]>
          # ovrd_user_group: <list or string>
          # profile: <list or string>
          # profile_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          # profile_type: <value in [list, radius]>
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
        '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/override'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'webfilter_profile_override': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'ovrd-cookie': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'ovrd-dur': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ovrd-dur-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['constant', 'ask'], 'type': 'str'},
                'ovrd-scope': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['user', 'user-group', 'ip', 'ask', 'browser'], 'type': 'str'},
                'ovrd-user-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'profile-attribute': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': [
                        'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                        'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Zone',
                        'Acct-Session-Id', 'Acct-Multi-Session-Id'
                    ],
                    'type': 'str'
                },
                'profile-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['list', 'radius'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_override'),
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
