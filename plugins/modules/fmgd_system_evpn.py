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
module: fmgd_system_evpn
short_description: Configure EVPN instance.
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
  system_evpn:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      arp_suppression:
        aliases: ['arp-suppression']
        type: str
        description: Enable/disable ARP suppression.
        choices: ['disable', 'enable']
      export_rt:
        aliases: ['export-rt']
        type: list
        elements: str
        description: List of export route targets.
      id:
        type: int
        description: ID.
        required: true
      import_rt:
        aliases: ['import-rt']
        type: list
        elements: str
        description: List of import route targets.
      ip_local_learning:
        aliases: ['ip-local-learning']
        type: str
        description: Enable/disable IP address local learning.
        choices: ['disable', 'enable']
      rd:
        type: str
        description: Route Distinguisher
      adv_default_gw:
        aliases: ['adv-default-gw']
        type: str
        description: Enable/disable advertisement of default gateway.
        choices: ['disable', 'enable']
      distribute_local_route:
        aliases: ['distribute-local-route']
        type: str
        description: Enable/disable distribution of local EVPN routes as IPv4 routes to BGP.
        choices: ['disable', 'enable']
      interface:
        type: list
        elements: str
        description: Outgoing interface for all VxLANs in this L3VRF EVPN instance.
      l3_instance:
        aliases: ['l3-instance']
        type: list
        elements: str
        description: L3VRF EVPN instance ID.
      type:
        type: str
        description: EVPN instance type.
        choices: ['macvrf', 'ipvrf']
      virtual_mac_vrid:
        aliases: ['virtual-mac-vrid']
        type: int
        description: VRID used to generate virtual MAC address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure EVPN instance.
      fortinet.fmgdevice.fmgd_system_evpn:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_evpn:
          id: 0 # Required variable, integer
          # arp_suppression: <value in [disable, enable]>
          # export_rt: <list or string>
          # import_rt: <list or string>
          # ip_local_learning: <value in [disable, enable]>
          # rd: <string>
          # adv_default_gw: <value in [disable, enable]>
          # distribute_local_route: <value in [disable, enable]>
          # interface: <list or string>
          # l3_instance: <list or string>
          # type: <value in [macvrf, ipvrf]>
          # virtual_mac_vrid: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/evpn'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_evpn': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'arp-suppression': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'export-rt': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.3', '']], 'required': True, 'type': 'int'},
                'import-rt': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-local-learning': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rd': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'adv-default-gw': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'distribute-local-route': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'l3-instance': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['macvrf', 'ipvrf'], 'type': 'str'},
                'virtual-mac-vrid': {'v_range': [['8.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_evpn'),
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
