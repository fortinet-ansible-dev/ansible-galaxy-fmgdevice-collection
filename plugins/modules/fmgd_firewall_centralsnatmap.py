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
module: fmgd_firewall_centralsnatmap
short_description: Configure IPv4 and IPv6 central SNAT policies.
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
  firewall_centralsnatmap:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Central SNAT action.
        choices: ['bypass', 'masquerade', 'ippool']
      dst_addr:
        aliases: ['dst-addr']
        type: list
        elements: str
        description: IPv4 Destination address.
      dst_addr6:
        aliases: ['dst-addr6']
        type: list
        elements: str
        description: IPv6 Destination address.
      dstintf:
        type: list
        elements: str
        description: Destination interface name from available interfaces.
      ipv6:
        type: str
        description: Enable/disable IPv6.
        choices: ['disable', 'enable']
      nat_ippool:
        aliases: ['nat-ippool']
        type: list
        elements: str
        description: Name of the IP pools to be used to translate addresses from available IP Pools.
      nat_ippool6:
        aliases: ['nat-ippool6']
        type: list
        elements: str
        description: IPv6 pools to be used for source NAT.
      policyid:
        type: int
        description: Policy ID.
        required: true
      src_addr:
        aliases: ['src-addr']
        type: list
        elements: str
        description: Original source address.
      src_addr6:
        aliases: ['src-addr6']
        type: list
        elements: str
        description: Original IPV6 source address.
      srcintf:
        type: list
        elements: str
        description: Source interface name from available interfaces.
      status:
        type: str
        description: Enable/disable the active status of this policy.
        choices: ['disable', 'enable']
      protocol:
        type: int
        description: Integer value for the protocol type
      orig_port:
        aliases: ['orig-port']
        type: str
        description: Original TCP port
      dst_port:
        aliases: ['dst-port']
        type: str
        description: Destination port or port range
      nat64:
        type: str
        description: Enable/disable NAT64.
        choices: ['disable', 'enable']
      nat46:
        type: str
        description: Enable/disable NAT46.
        choices: ['disable', 'enable']
      comments:
        type: str
        description: Comment.
      orig_addr6:
        aliases: ['orig-addr6']
        type: list
        elements: str
        description: IPv6 Original address.
      nat:
        type: str
        description: Enable/disable source NAT.
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
      nat_port:
        aliases: ['nat-port']
        type: str
        description: Translated port or port range
      orig_addr:
        aliases: ['orig-addr']
        type: list
        elements: str
        description: IPv4 Original address.
      port_preserve:
        aliases: ['port-preserve']
        type: str
        description: Enable/disable preservation of the original source port from source NAT if it has not been used.
        choices: ['disable', 'enable']
      type:
        type: str
        description: IPv4/IPv6 source NAT.
        choices: ['ipv4', 'ipv6']
      port_random:
        aliases: ['port-random']
        type: str
        description: Enable/disable random source port selection for source NAT.
        choices: ['disable', 'enable']
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv4 and IPv6 central SNAT policies.
      fortinet.fmgdevice.fmgd_firewall_centralsnatmap:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_centralsnatmap:
          policyid: 0 # Required variable, integer
          # action: <value in [bypass, masquerade, ippool]>
          # dst_addr: <list or string>
          # dst_addr6: <list or string>
          # dstintf: <list or string>
          # ipv6: <value in [disable, enable]>
          # nat_ippool: <list or string>
          # nat_ippool6: <list or string>
          # src_addr: <list or string>
          # src_addr6: <list or string>
          # srcintf: <list or string>
          # status: <value in [disable, enable]>
          # protocol: <integer>
          # orig_port: <string>
          # dst_port: <string>
          # nat64: <value in [disable, enable]>
          # nat46: <value in [disable, enable]>
          # comments: <string>
          # orig_addr6: <list or string>
          # nat: <value in [disable, enable]>
          # uuid: <string>
          # nat_port: <string>
          # orig_addr: <list or string>
          # port_preserve: <value in [disable, enable]>
          # type: <value in [ipv4, ipv6]>
          # port_random: <value in [disable, enable]>
          # custom_tags: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/central-snat-map'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_centralsnatmap': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['bypass', 'masquerade', 'ippool'], 'type': 'str'},
                'dst-addr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dst-addr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ipv6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat-ippool': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'nat-ippool6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'src-addr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'src-addr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'orig-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dst-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'nat64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'orig-addr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'nat': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'nat-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'orig-addr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'port-preserve': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'port-random': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_centralsnatmap'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
