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
module: fmgd_switchcontroller_securitypolicy_admin
short_description: Configure fortiswitchs admin security-policy.
version_added: "1.2.0"
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
  switchcontroller_securitypolicy_admin:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auto:
        type: str
        description: Automatically set based on the host ip connected via the Fortilink interface.
        choices: ['disable', 'enable']
      ip6_trusthost1:
        aliases: ['ip6-trusthost1']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost10:
        aliases: ['ip6-trusthost10']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost2:
        aliases: ['ip6-trusthost2']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost3:
        aliases: ['ip6-trusthost3']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost4:
        aliases: ['ip6-trusthost4']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost5:
        aliases: ['ip6-trusthost5']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost6:
        aliases: ['ip6-trusthost6']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost7:
        aliases: ['ip6-trusthost7']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost8:
        aliases: ['ip6-trusthost8']
        type: str
        description: Trusted IPv6 host.
      ip6_trusthost9:
        aliases: ['ip6-trusthost9']
        type: str
        description: Trusted IPv6 host.
      name:
        type: str
        description: Policy name.
        required: true
      trusthost1:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost10:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost2:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost3:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost4:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost5:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost6:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost7:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost8:
        type: list
        elements: str
        description: Trusted IPv4 host.
      trusthost9:
        type: list
        elements: str
        description: Trusted IPv4 host.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure fortiswitchs admin security-policy.
      fortinet.fmgdevice.fmgd_switchcontroller_securitypolicy_admin:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_securitypolicy_admin:
          name: "your value" # Required variable, string
          # auto: <value in [disable, enable]>
          # ip6_trusthost1: <string>
          # ip6_trusthost10: <string>
          # ip6_trusthost2: <string>
          # ip6_trusthost3: <string>
          # ip6_trusthost4: <string>
          # ip6_trusthost5: <string>
          # ip6_trusthost6: <string>
          # ip6_trusthost7: <string>
          # ip6_trusthost8: <string>
          # ip6_trusthost9: <string>
          # trusthost1: <list or string>
          # trusthost10: <list or string>
          # trusthost2: <list or string>
          # trusthost3: <list or string>
          # trusthost4: <list or string>
          # trusthost5: <list or string>
          # trusthost6: <list or string>
          # trusthost7: <list or string>
          # trusthost8: <list or string>
          # trusthost9: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/admin'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_securitypolicy_admin': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'auto': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-trusthost1': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost10': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost2': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost3': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost4': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost5': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost6': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost7': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost8': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ip6-trusthost9': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'trusthost1': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost10': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost2': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost3': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost4': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost5': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost6': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost7': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost8': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'trusthost9': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_securitypolicy_admin'),
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
