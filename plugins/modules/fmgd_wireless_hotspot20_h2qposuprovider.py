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
module: fmgd_wireless_hotspot20_h2qposuprovider
short_description: Configure online sign up
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
  wireless_hotspot20_h2qposuprovider:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      friendly_name:
        aliases: ['friendly-name']
        type: list
        elements: dict
        description: Friendly name.
        suboptions:
          friendly_name:
            aliases: ['friendly-name']
            type: str
            description: OSU provider friendly name.
          index:
            type: int
            description: OSU provider friendly name index.
          lang:
            type: str
            description: Language code.
      icon:
        type: list
        elements: str
        description: OSU provider icon.
      name:
        type: str
        description: OSU provider ID.
        required: true
      osu_method:
        aliases: ['osu-method']
        type: list
        elements: str
        description: OSU method list.
        choices: ['oma-dm', 'soap-xml-spp', 'reserved']
      osu_nai:
        aliases: ['osu-nai']
        type: str
        description: OSU NAI.
      server_uri:
        aliases: ['server-uri']
        type: str
        description: Server URI.
      service_description:
        aliases: ['service-description']
        type: list
        elements: dict
        description: Service description.
        suboptions:
          lang:
            type: str
            description: Language code.
          service_description:
            aliases: ['service-description']
            type: str
            description: Service description.
          service_id:
            aliases: ['service-id']
            type: int
            description: OSU service ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure online sign up
      fortinet.fmgdevice.fmgd_wireless_hotspot20_h2qposuprovider:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_hotspot20_h2qposuprovider:
          name: "your value" # Required variable, string
          # friendly_name:
          #   - friendly_name: <string>
          #     index: <integer>
          #     lang: <string>
          # icon: <list or string>
          # osu_method: ["oma-dm", "soap-xml-spp", "reserved"]
          # osu_nai: <string>
          # server_uri: <string>
          # service_description:
          #   - lang: <string>
          #     service_description: <string>
          #     service_id: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_hotspot20_h2qposuprovider': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'friendly-name': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'friendly-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'index': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'lang': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'icon': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'osu-method': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['oma-dm', 'soap-xml-spp', 'reserved'],
                    'elements': 'str'
                },
                'osu-nai': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'server-uri': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'service-description': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'lang': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'service-description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'service-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_hotspot20_h2qposuprovider'),
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
