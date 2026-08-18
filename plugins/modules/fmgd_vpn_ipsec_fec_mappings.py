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
module: fmgd_vpn_ipsec_fec_mappings
short_description: FEC redundancy mapping table.
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
  fec:
    description: The parameter (fec) in requested url.
    type: str
    required: true
  vpn_ipsec_fec_mappings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bandwidth_bi_threshold:
        aliases: ['bandwidth-bi-threshold']
        type: int
        description: Apply FEC parameters when available bi-bandwidth is >= threshold
      bandwidth_down_threshold:
        aliases: ['bandwidth-down-threshold']
        type: int
        description: Apply FEC parameters when available down bandwidth is >= threshold
      bandwidth_up_threshold:
        aliases: ['bandwidth-up-threshold']
        type: int
        description: Apply FEC parameters when available up bandwidth is >= threshold
      base:
        type: int
        description: Number of base FEC packets
      latency_threshold:
        aliases: ['latency-threshold']
        type: int
        description: Apply FEC parameters when latency is
      packet_loss_threshold:
        aliases: ['packet-loss-threshold']
        type: int
        description: Apply FEC parameters when packet loss is >= threshold
      redundant:
        type: int
        description: Number of redundant FEC packets
      seqno:
        type: int
        description: Sequence number
      bandwidth_bi_threshold_negate:
        aliases: ['bandwidth-bi-threshold-negate']
        type: str
        description: Negate bi-bandwidth threshold.
        choices: ['disable', 'enable']
      bandwidth_down_threshold_negate:
        aliases: ['bandwidth-down-threshold-negate']
        type: str
        description: Negate down bandwidth threshold.
        choices: ['disable', 'enable']
      bandwidth_up_threshold_negate:
        aliases: ['bandwidth-up-threshold-negate']
        type: str
        description: Negate up bandwidth threshold.
        choices: ['disable', 'enable']
      latency_threshold_negate:
        aliases: ['latency-threshold-negate']
        type: str
        description: Negate latency threshold.
        choices: ['disable', 'enable']
      packet_loss_threshold_negate:
        aliases: ['packet-loss-threshold-negate']
        type: str
        description: Negate packet loss threshold.
        choices: ['disable', 'enable']
      tos:
        type: list
        elements: dict
        description: Tos.
        suboptions:
          base:
            type: int
            description: Number of base FEC packets
          redundant:
            type: int
            description: Number of redundant FEC packets
          seqno:
            type: int
            description: Sequence number
          tos:
            type: str
            description: Type of service bit pattern.
          tos_mask:
            aliases: ['tos-mask']
            type: str
            description: Type of service evaluated bits.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FEC redundancy mapping table.
      fortinet.fmgdevice.fmgd_vpn_ipsec_fec_mappings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        fec: <your own value>
        state: present # <value in [present, absent]>
        vpn_ipsec_fec_mappings:
          # bandwidth_bi_threshold: <integer>
          # bandwidth_down_threshold: <integer>
          # bandwidth_up_threshold: <integer>
          # base: <integer>
          # latency_threshold: <integer>
          # packet_loss_threshold: <integer>
          # redundant: <integer>
          # seqno: <integer>
          # bandwidth_bi_threshold_negate: <value in [disable, enable]>
          # bandwidth_down_threshold_negate: <value in [disable, enable]>
          # bandwidth_up_threshold_negate: <value in [disable, enable]>
          # latency_threshold_negate: <value in [disable, enable]>
          # packet_loss_threshold_negate: <value in [disable, enable]>
          # tos:
          #   - base: <integer>
          #     redundant: <integer>
          #     seqno: <integer>
          #     tos: <string>
          #     tos_mask: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/fec/{fec}/mappings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'fec': {'required': True, 'type': 'str'},
        'vpn_ipsec_fec_mappings': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'bandwidth-bi-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'bandwidth-down-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'bandwidth-up-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'base': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'latency-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'packet-loss-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'redundant': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'seqno': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'bandwidth-bi-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bandwidth-down-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bandwidth-up-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'latency-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'packet-loss-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'base': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'redundant': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'seqno': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'tos': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'tos-mask': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_fec_mappings'),
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
