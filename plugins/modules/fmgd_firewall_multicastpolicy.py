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
module: fmgd_firewall_multicastpolicy
short_description: Configure multicast NAT policies.
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
  firewall_multicastpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Accept or deny traffic matching the policy.
        choices: ['deny', 'accept']
      auto_asic_offload:
        aliases: ['auto-asic-offload']
        type: str
        description: Enable/disable offloading policy traffic for hardware acceleration.
        choices: ['disable', 'enable']
      comments:
        type: str
        description: Comment.
      dnat:
        type: str
        description: IPv4 DNAT address used for multicast destination addresses.
      dstaddr:
        type: list
        elements: str
        description: Destination address objects.
      dstintf:
        type: list
        elements: str
        description: Destination interface name.
      end_port:
        aliases: ['end-port']
        type: int
        description: Integer value for ending TCP/UDP/SCTP destination port in range
      id:
        type: int
        description: Policy ID
        required: true
      ips_sensor:
        aliases: ['ips-sensor']
        type: list
        elements: str
        description: Name of an existing IPS sensor.
      logtraffic:
        type: str
        description: Enable or disable logging.
        choices: ['disable', 'all', 'utm', 'enable']
      name:
        type: str
        description: Policy name.
      protocol:
        type: int
        description: Integer value for the protocol type as defined by IANA
      snat:
        type: str
        description: Enable/disable substitution of the outgoing interface IP address for the original source IP address
        choices: ['disable', 'enable']
      snat_ip:
        aliases: ['snat-ip']
        type: str
        description: IPv4 address to be used as the source address for NATed traffic.
      srcaddr:
        type: list
        elements: str
        description: Source address objects.
      srcintf:
        type: list
        elements: str
        description: Source interface name.
      start_port:
        aliases: ['start-port']
        type: int
        description: Integer value for starting TCP/UDP/SCTP destination port in range
      status:
        type: str
        description: Enable/disable this policy.
        choices: ['disable', 'enable']
      traffic_shaper:
        aliases: ['traffic-shaper']
        type: list
        elements: str
        description: Traffic shaper to apply to traffic forwarded by the multicast policy.
      utm_status:
        aliases: ['utm-status']
        type: str
        description: Enable to add an IPS security profile to the policy.
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
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
    - name: Configure multicast NAT policies.
      fortinet.fmgdevice.fmgd_firewall_multicastpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_multicastpolicy:
          id: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # auto_asic_offload: <value in [disable, enable]>
          # comments: <string>
          # dnat: <string>
          # dstaddr: <list or string>
          # dstintf: <list or string>
          # end_port: <integer>
          # ips_sensor: <list or string>
          # logtraffic: <value in [disable, all, utm, ...]>
          # name: <string>
          # protocol: <integer>
          # snat: <value in [disable, enable]>
          # snat_ip: <string>
          # srcaddr: <list or string>
          # srcintf: <list or string>
          # start_port: <integer>
          # status: <value in [disable, enable]>
          # traffic_shaper: <list or string>
          # utm_status: <value in [disable, enable]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_multicastpolicy': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'auto-asic-offload': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dnat': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'end-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ips-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logtraffic': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'all', 'utm', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'snat': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'snat-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'start-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'utm-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_multicastpolicy'),
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
