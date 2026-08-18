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
module: fmgd_webproxy_fastfallback
short_description: Proxy destination connection fast-fallback.
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
  webproxy_fastfallback:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      connection_mode:
        aliases: ['connection-mode']
        type: str
        description: Connection mode for multiple destinations.
        choices: ['sequentially', 'simultaneously']
      connection_timeout:
        aliases: ['connection-timeout']
        type: int
        description: Number of milliseconds to wait before starting another connection
      name:
        type: str
        description: Configure a name for the fast-fallback entry.
        required: true
      protocol:
        type: str
        description: Connection protocols for multiple destinations.
        choices: ['IPv4-first', 'IPv6-first', 'IPv4-only', 'IPv6-only']
      status:
        type: str
        description: Enable/disable the fast-fallback entry.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Proxy destination connection fast-fallback.
      fortinet.fmgdevice.fmgd_webproxy_fastfallback:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        webproxy_fastfallback:
          name: "your value" # Required variable, string
          # connection_mode: <value in [sequentially, simultaneously]>
          # connection_timeout: <integer>
          # protocol: <value in [IPv4-first, IPv6-first, IPv4-only, ...]>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/web-proxy/fast-fallback'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'webproxy_fastfallback': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'connection-mode': {'v_range': [['7.4.3', '']], 'choices': ['sequentially', 'simultaneously'], 'type': 'str'},
                'connection-timeout': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.3', '']], 'required': True, 'type': 'str'},
                'protocol': {'v_range': [['7.4.3', '']], 'choices': ['IPv4-first', 'IPv6-first', 'IPv4-only', 'IPv6-only'], 'type': 'str'},
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_fastfallback'),
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
