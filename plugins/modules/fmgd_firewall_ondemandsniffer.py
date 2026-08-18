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
module: fmgd_firewall_ondemandsniffer
short_description: Configure on-demand packet sniffer.
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
  firewall_ondemandsniffer:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      advanced_filter:
        aliases: ['advanced-filter']
        type: str
        description: Advanced freeform filter that will be used over existing filter settings if set.
      hosts:
        type: list
        elements: str
        description: IPv4 or IPv6 hosts to filter in this traffic sniffer.
      interface:
        type: list
        elements: str
        description: Interface name that on-demand packet sniffer will take place.
      max_packet_count:
        aliases: ['max-packet-count']
        type: int
        description: Maximum number of packets to capture per on-demand packet sniffer.
      name:
        type: str
        description: On-demand packet sniffer name.
        required: true
      non_ip_packet:
        aliases: ['non-ip-packet']
        type: str
        description: Include non-IP packets.
        choices: ['disable', 'enable']
      ports:
        type: list
        elements: int
        description: Ports to filter for in this traffic sniffer.
      protocols:
        type: list
        elements: int
        description: Protocols to filter in this traffic sniffer.
      hostnames:
        type: list
        elements: str
        description: Hostnames.
      snapshot_length:
        aliases: ['snapshot-length']
        type: int
        description: Snapshot length.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure on-demand packet sniffer.
      fortinet.fmgdevice.fmgd_firewall_ondemandsniffer:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_ondemandsniffer:
          name: "your value" # Required variable, string
          # advanced_filter: <string>
          # hosts: <list or string>
          # interface: <list or string>
          # max_packet_count: <integer>
          # non_ip_packet: <value in [disable, enable]>
          # ports: <list or integer>
          # protocols: <list or integer>
          # hostnames: <list or string>
          # snapshot_length: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/on-demand-sniffer'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_ondemandsniffer': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'advanced-filter': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'hosts': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'max-packet-count': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.3', '']], 'required': True, 'type': 'str'},
                'non-ip-packet': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ports': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'protocols': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'hostnames': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'snapshot-length': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ondemandsniffer'),
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
