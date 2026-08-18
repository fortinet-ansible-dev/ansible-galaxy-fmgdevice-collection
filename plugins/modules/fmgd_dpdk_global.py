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
module: fmgd_dpdk_global
short_description: Configure global DPDK options.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  dpdk_global:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      elasticbuffer:
        type: str
        description: Enable/disable elasticbuffer support for all DPDK ports.
        choices: ['disable', 'enable']
      hugepage_percentage:
        aliases: ['hugepage-percentage']
        type: int
        description: Percentage of main memory allocated to hugepages, which are available for DPDK operation.
      interface:
        type: list
        elements: str
        description: Physical interfaces that enable DPDK.
      ipsec_offload:
        aliases: ['ipsec-offload']
        type: str
        description: Enable/disable DPDK IPsec phase 2 offloading.
        choices: ['disable', 'enable']
      mbufpool_percentage:
        aliases: ['mbufpool-percentage']
        type: int
        description: Percentage of main memory allocated to DPDK packet buffer.
      multiqueue:
        type: str
        description: Enable/disable multi-queue RX/TX support for all DPDK ports.
        choices: ['disable', 'enable']
      per_session_accounting:
        aliases: ['per-session-accounting']
        type: str
        description: Enable/disable per-session accounting.
        choices: ['enable', 'disable', 'traffic-log-only']
      protects:
        type: str
        description: Special arguments for device
      sleep_on_idle:
        aliases: ['sleep-on-idle']
        type: str
        description: Enable/disable sleep-on-idle support for all FDH engines.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable DPDK operation for the entire system.
        choices: ['disable', 'enable']
      session_table_percentage:
        aliases: ['session-table-percentage']
        type: int
        description: Percentage of main memory allocated to DPDK session table.
      frag_offload:
        aliases: ['frag-offload']
        type: str
        description: Enable/disable DPDK fragmentation/defragmentation offloading
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure global DPDK options.
      fortinet.fmgdevice.fmgd_dpdk_global:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        dpdk_global:
          # elasticbuffer: <value in [disable, enable]>
          # hugepage_percentage: <integer>
          # interface: <list or string>
          # ipsec_offload: <value in [disable, enable]>
          # mbufpool_percentage: <integer>
          # multiqueue: <value in [disable, enable]>
          # per_session_accounting: <value in [enable, disable, traffic-log-only]>
          # protects: <string>
          # sleep_on_idle: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # session_table_percentage: <integer>
          # frag_offload: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/dpdk/global'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'dpdk_global': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'elasticbuffer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hugepage-percentage': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipsec-offload': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mbufpool-percentage': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'multiqueue': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-session-accounting': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['enable', 'disable', 'traffic-log-only'],
                    'type': 'str'
                },
                'protects': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'sleep-on-idle': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-table-percentage': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'frag-offload': {'v_range': [['7.4.9', '7.4.11'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dpdk_global'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
