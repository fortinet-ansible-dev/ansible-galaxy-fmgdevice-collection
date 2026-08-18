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
module: fmgd_system_dnp3proxy
short_description: Configure dnpproxy settings.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_dnp3proxy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      port:
        type: int
        description: DNP3 TCPServer Port.
      status:
        type: str
        description: Enable/disable DNP daemon.
        choices: ['disable', 'enable']
      term_baudrate:
        aliases: ['term-baudrate']
        type: str
        description: Term Baudrate.
        choices: ['9600', '19200', '38400', '115200']
      term_databits:
        aliases: ['term-databits']
        type: int
        description: Term Data Bits.
      term_flowcontrol:
        aliases: ['term-flowcontrol']
        type: str
        description: Term Flow Control
        choices: ['none', 'xon_xoff', 'hardware']
      term_parity:
        aliases: ['term-parity']
        type: str
        description: Term Parity
        choices: ['none', 'odd', 'even']
      term_stopbits:
        aliases: ['term-stopbits']
        type: int
        description: Term Stop Bits.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure dnpproxy settings.
      fortinet.fmgdevice.fmgd_system_dnp3proxy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_dnp3proxy:
          # port: <integer>
          # status: <value in [disable, enable]>
          # term_baudrate: <value in [9600, 19200, 38400, ...]>
          # term_databits: <integer>
          # term_flowcontrol: <value in [none, xon_xoff, hardware]>
          # term_parity: <value in [none, odd, even]>
          # term_stopbits: <integer>
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
        '/pm/config/device/{device}/global/system/dnp3-proxy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_dnp3proxy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'term-baudrate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['9600', '19200', '38400', '115200'], 'type': 'str'},
                'term-databits': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'term-flowcontrol': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'xon_xoff', 'hardware'], 'type': 'str'},
                'term-parity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'odd', 'even'], 'type': 'str'},
                'term-stopbits': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dnp3proxy'),
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
