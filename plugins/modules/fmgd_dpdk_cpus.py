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
module: fmgd_dpdk_cpus
short_description: Configure CPUs enabled to run engines in each DPDK stage.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  dpdk_cpus:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ips_cpus:
        aliases: ['ips-cpus']
        type: str
        description: CPUs enabled to run DPDK IPS engines.
      isolated_cpus:
        aliases: ['isolated-cpus']
        type: str
        description: CPUs isolated to run only the DPDK engines with the exception of processes that have affinity explicitly set by either a user conf...
      rx_cpus:
        aliases: ['rx-cpus']
        type: str
        description: CPUs enabled to run DPDK RX engines.
      tx_cpus:
        aliases: ['tx-cpus']
        type: str
        description: CPUs enabled to run DPDK TX engines.
      vnp_cpus:
        aliases: ['vnp-cpus']
        type: str
        description: CPUs enabled to run DPDK VNP engines.
      vnpsp_cpus:
        aliases: ['vnpsp-cpus']
        type: str
        description: CPUs enabled to run DPDK VNP slow path.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure CPUs enabled to run engines in each DPDK stage.
      fortinet.fmgdevice.fmgd_dpdk_cpus:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        dpdk_cpus:
          # ips_cpus: <string>
          # isolated_cpus: <string>
          # rx_cpus: <string>
          # tx_cpus: <string>
          # vnp_cpus: <string>
          # vnpsp_cpus: <string>
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
        '/pm/config/device/{device}/global/dpdk/cpus'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'dpdk_cpus': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'ips-cpus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'isolated-cpus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'rx-cpus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'tx-cpus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vnp-cpus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vnpsp-cpus': {'v_range': [['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dpdk_cpus'),
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
