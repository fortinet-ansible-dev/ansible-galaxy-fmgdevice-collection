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
module: fmgd_ztna_connectorserviceedge
short_description: Device vdom ztna connector service edge
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  ztna_connectorserviceedge:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      interface:
        type: list
        elements: str
        description: Interface.
      port:
        type: int
        description: Port.
      server_cert:
        aliases: ['server-cert']
        type: list
        elements: str
        description: Server cert.
      ssl_max_version:
        aliases: ['ssl-max-version']
        type: str
        description: Ssl max version.
        choices: ['tls-1.1', 'tls-1.2', 'tls-1.3']
      status:
        type: str
        description: Status.
        choices: ['disable', 'enable']
      trusted_client_ca:
        aliases: ['trusted-client-ca']
        type: list
        elements: str
        description: Trusted client ca.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom ztna connector service edge
      fortinet.fmgdevice.fmgd_ztna_connectorserviceedge:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        ztna_connectorserviceedge:
          # interface: <list or string>
          # port: <integer>
          # server_cert: <list or string>
          # ssl_max_version: <value in [tls-1.1, tls-1.2, tls-1.3]>
          # status: <value in [disable, enable]>
          # trusted_client_ca: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/ztna/connector-service-edge'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ztna_connectorserviceedge': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'server-cert': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-max-version': {'v_range': [['7.6.4', '']], 'choices': ['tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-client-ca': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_connectorserviceedge'),
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
