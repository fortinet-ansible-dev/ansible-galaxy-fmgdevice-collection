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
module: fmgd_system_vxlan
short_description: Configure VXLAN devices.
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
  system_vxlan:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dstport:
        type: int
        description: VXLAN destination port
      evpn_id:
        aliases: ['evpn-id']
        type: list
        elements: str
        description: EVPN instance.
      interface:
        type: list
        elements: str
        description: Outgoing interface for VXLAN encapsulated traffic.
      ip_version:
        aliases: ['ip-version']
        type: str
        description: IP version to use for the VXLAN interface and so for communication over the VXLAN.
        choices: ['ipv4-unicast', 'ipv6-unicast', 'ipv4-multicast', 'ipv6-multicast']
      learn_from_traffic:
        aliases: ['learn-from-traffic']
        type: str
        description: Enable/disable VXLAN MAC learning from traffic.
        choices: ['disable', 'enable']
      multicast_ttl:
        aliases: ['multicast-ttl']
        type: int
        description: VXLAN multicast TTL
      name:
        type: str
        description: VXLAN device or interface name.
        required: true
      remote_ip:
        aliases: ['remote-ip']
        type: list
        elements: str
        description: IPv4 address of the VXLAN interface on the device at the remote end of the VXLAN.
      remote_ip6:
        aliases: ['remote-ip6']
        type: list
        elements: str
        description: IPv6 IP address of the VXLAN interface on the device at the remote end of the VXLAN.
      vni:
        type: int
        description: VXLAN network ID.
      local_ip6:
        aliases: ['local-ip6']
        type: str
        description: IPv6 address to use as the source address for egress VXLAN packets.
      local_ip:
        aliases: ['local-ip']
        type: str
        description: IPv4 address to use as the source address for egress VXLAN packets.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure VXLAN devices.
      fortinet.fmgdevice.fmgd_system_vxlan:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_vxlan:
          name: "your value" # Required variable, string
          # dstport: <integer>
          # evpn_id: <list or string>
          # interface: <list or string>
          # ip_version: <value in [ipv4-unicast, ipv6-unicast, ipv4-multicast, ...]>
          # learn_from_traffic: <value in [disable, enable]>
          # multicast_ttl: <integer>
          # remote_ip: <list or string>
          # remote_ip6: <list or string>
          # vni: <integer>
          # local_ip6: <string>
          # local_ip: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/vxlan'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_vxlan': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'dstport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'evpn-id': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-version': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['ipv4-unicast', 'ipv6-unicast', 'ipv4-multicast', 'ipv6-multicast'],
                    'type': 'str'
                },
                'learn-from-traffic': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-ttl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'remote-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remote-ip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vni': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'local-ip6': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'local-ip': {'v_range': [['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vxlan'),
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
