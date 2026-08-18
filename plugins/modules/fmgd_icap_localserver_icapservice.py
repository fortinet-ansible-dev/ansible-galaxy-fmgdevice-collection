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
module: fmgd_icap_localserver_icapservice
short_description: Device vdom icap local server icap service
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
  local-server:
    description: Deprecated, please use "local_server"
    type: str
  local_server:
    description: The parameter (local-server) in requested url.
    type: str
  icap_localserver_icapservice:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      av_profile:
        aliases: ['av-profile']
        type: list
        elements: str
        description: Name of an existing Antivirus profile.
      dlp_profile:
        aliases: ['dlp-profile']
        type: list
        elements: str
        description: Dlp profile.
      dlp_sensor:
        aliases: ['dlp-sensor']
        type: list
        elements: str
        description: Name of an existing DLP sensor.
      extension_headers:
        aliases: ['extension-headers']
        type: list
        elements: str
        description: Extension headers.
        choices: ['X-Virus-id', 'X-Infection-Found', 'X-Violation-Found']
      image_analyzer_profile:
        aliases: ['image-analyzer-profile']
        type: list
        elements: str
        description: Image analyzer profile.
      name:
        type: str
        description: Name of ICAP service profile.
        required: true
      profile_protocol_options:
        aliases: ['profile-protocol-options']
        type: list
        elements: str
        description: Profile protocol options.
      service_id:
        aliases: ['service-id']
        type: int
        description: ID of the ICAP server service.
      webfilter_profile:
        aliases: ['webfilter-profile']
        type: list
        elements: str
        description: Name of an existing Web filter profile.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom icap local server icap service
      fortinet.fmgdevice.fmgd_icap_localserver_icapservice:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        local_server: <your own value>
        state: present # <value in [present, absent]>
        icap_localserver_icapservice:
          name: "your value" # Required variable, string
          # av_profile: <list or string>
          # dlp_profile: <list or string>
          # dlp_sensor: <list or string>
          # extension_headers: ["X-Virus-id", "X-Infection-Found", "X-Violation-Found"]
          # image_analyzer_profile: <list or string>
          # profile_protocol_options: <list or string>
          # service_id: <integer>
          # webfilter_profile: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/icap/local-server/{local-server}/icap-service'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'local-server': {'type': 'str', 'api_name': 'local_server'},
        'local_server': {'type': 'str'},
        'icap_localserver_icapservice': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'av-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'extension-headers': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['X-Virus-id', 'X-Infection-Found', 'X-Violation-Found'],
                    'elements': 'str'
                },
                'image-analyzer-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'profile-protocol-options': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'webfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_localserver_icapservice'),
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
