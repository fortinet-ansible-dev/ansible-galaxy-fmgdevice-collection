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
module: fmgd_firewall_internetserviceextension_disableentry_portrange
short_description: Port ranges in the disable entry.
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
  internet-service-extension:
    description: Deprecated, please use "internet_service_extension"
    type: str
  internet_service_extension:
    description: The parameter (internet-service-extension) in requested url.
    type: str
  disable-entry:
    description: Deprecated, please use "disable_entry"
    type: str
  disable_entry:
    description: The parameter (disable-entry) in requested url.
    type: str
  firewall_internetserviceextension_disableentry_portrange:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      end_port:
        aliases: ['end-port']
        type: int
        description: Ending TCP/UDP/SCTP destination port
      id:
        type: int
        description: Custom entry port range ID.
        required: true
      start_port:
        aliases: ['start-port']
        type: int
        description: Starting TCP/UDP/SCTP destination port
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Port ranges in the disable entry.
      fortinet.fmgdevice.fmgd_firewall_internetserviceextension_disableentry_portrange:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        internet_service_extension: <your own value>
        disable_entry: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetserviceextension_disableentry_portrange:
          id: 0 # Required variable, integer
          # end_port: <integer>
          # start_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'internet-service-extension': {'type': 'str', 'api_name': 'internet_service_extension'},
        'internet_service_extension': {'type': 'str'},
        'disable-entry': {'type': 'str', 'api_name': 'disable_entry'},
        'disable_entry': {'type': 'str'},
        'firewall_internetserviceextension_disableentry_portrange': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']],
            'options': {
                'end-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']], 'required': True, 'type': 'int'},
                'start-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetserviceextension_disableentry_portrange'),
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
