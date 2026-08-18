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
module: fmgd_wireless_bonjourprofile_policylist
short_description: Bonjour policy list.
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
  bonjour-profile:
    description: Deprecated, please use "bonjour_profile"
    type: str
  bonjour_profile:
    description: The parameter (bonjour-profile) in requested url.
    type: str
  wireless_bonjourprofile_policylist:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description.
      from_vlan:
        aliases: ['from-vlan']
        type: str
        description: VLAN ID from which the Bonjour service is advertised
      policy_id:
        aliases: ['policy-id']
        type: int
        description: Policy ID.
      services:
        type: list
        elements: str
        description: Bonjour services for the VLAN connecting to the Bonjour network.
        choices: ['airplay', 'afp', 'bit-torrent', 'ftp', 'ichat', 'itunes', 'printers', 'samba',
                  'scanners', 'ssh', 'chromecast', 'all', 'miracast']
      to_vlan:
        aliases: ['to-vlan']
        type: str
        description: VLAN ID to which the Bonjour service is made available
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Bonjour policy list.
      fortinet.fmgdevice.fmgd_wireless_bonjourprofile_policylist:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        bonjour_profile: <your own value>
        state: present # <value in [present, absent]>
        wireless_bonjourprofile_policylist:
          # description: <string>
          # from_vlan: <string>
          # policy_id: <integer>
          # services: ["airplay", "afp", "bit-torrent", "ftp", "ichat", "itunes", "printers",
          #            "samba", "scanners", "ssh", "chromecast", "all", "miracast"]
          # to_vlan: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'bonjour-profile': {'type': 'str', 'api_name': 'bonjour_profile'},
        'bonjour_profile': {'type': 'str'},
        'wireless_bonjourprofile_policylist': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'from-vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'policy-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'services': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'airplay', 'afp', 'bit-torrent', 'ftp', 'ichat', 'itunes', 'printers', 'samba', 'scanners', 'ssh', 'chromecast', 'all',
                        'miracast'
                    ],
                    'elements': 'str'
                },
                'to-vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_bonjourprofile_policylist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
