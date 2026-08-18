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
module: fmgd_system_fabricvpn_overlays
short_description: Local overlay interfaces table.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_fabricvpn_overlays:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bgp_neighbor:
        aliases: ['bgp-neighbor']
        type: list
        elements: str
        description: Underlying BGP neighbor entry.
      bgp_neighbor_group:
        aliases: ['bgp-neighbor-group']
        type: list
        elements: str
        description: Underlying BGP neighbor group entry.
      bgp_neighbor_range:
        aliases: ['bgp-neighbor-range']
        type: list
        elements: str
        description: Underlying BGP neighbor range entry.
      bgp_network:
        aliases: ['bgp-network']
        type: list
        elements: str
        description: Underlying BGP network.
      interface:
        type: list
        elements: str
        description: Underlying interface name.
      ipsec_phase1:
        aliases: ['ipsec-phase1']
        type: list
        elements: str
        description: IPsec interface.
      name:
        type: str
        description: Overlay name.
        required: true
      overlay_policy:
        aliases: ['overlay-policy']
        type: list
        elements: str
        description: The overlay policy to allow ADVPN thru traffic.
      overlay_tunnel_block:
        aliases: ['overlay-tunnel-block']
        type: list
        elements: str
        description: IPv4 address and subnet mask for the overlay tunnel , syntax
      remote_gw:
        aliases: ['remote-gw']
        type: str
        description: IP address of the hub gateway
      route_policy:
        aliases: ['route-policy']
        type: list
        elements: str
        description: Underlying router policy.
      sdwan_member:
        aliases: ['sdwan-member']
        type: list
        elements: str
        description: Reference to SD-WAN member entry.
      ipsec_network_id:
        aliases: ['ipsec-network-id']
        type: int
        description: VPN gateway network ID.
      overlay_tunnel_block_ipam:
        aliases: ['overlay-tunnel-block-ipam']
        type: list
        elements: str
        description: Source for the overlay tunnel, obtained from the firewall addresses managed by IPAM
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Local overlay interfaces table.
      fortinet.fmgdevice.fmgd_system_fabricvpn_overlays:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_fabricvpn_overlays:
          name: "your value" # Required variable, string
          # bgp_neighbor: <list or string>
          # bgp_neighbor_group: <list or string>
          # bgp_neighbor_range: <list or string>
          # bgp_network: <list or string>
          # interface: <list or string>
          # ipsec_phase1: <list or string>
          # overlay_policy: <list or string>
          # overlay_tunnel_block: <list or string>
          # remote_gw: <string>
          # route_policy: <list or string>
          # sdwan_member: <list or string>
          # ipsec_network_id: <integer>
          # overlay_tunnel_block_ipam: <list or string>
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
        '/pm/config/device/{device}/global/system/fabric-vpn/overlays'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_fabricvpn_overlays': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'bgp-neighbor': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bgp-neighbor-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bgp-neighbor-range': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bgp-network': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipsec-phase1': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'overlay-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'overlay-tunnel-block': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remote-gw': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'route-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sdwan-member': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipsec-network-id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'overlay-tunnel-block-ipam': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fabricvpn_overlays'),
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
