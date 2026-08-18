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
module: fmgd_llm_proxy
short_description: Configure LLM Proxy.
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
  llm_proxy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      hostname:
        type: list
        elements: str
        description: Hostname.
      incoming_http_port:
        aliases: ['incoming-http-port']
        type: int
        description: Incoming http port.
      incoming_https_port:
        aliases: ['incoming-https-port']
        type: int
        description: Incoming https port.
      incoming_ip:
        aliases: ['incoming-ip']
        type: str
        description: Incoming ip.
      incoming_ip6:
        aliases: ['incoming-ip6']
        type: str
        description: Incoming ip6.
      interface:
        type: list
        elements: str
        description: Interface.
      ipv6_status:
        aliases: ['ipv6-status']
        type: str
        description: Ipv6 status.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Name.
      protocol:
        type: list
        elements: str
        description: Protocol.
        choices: ['http', 'https']
      srv_pool_max_concurrent_request:
        aliases: ['srv-pool-max-concurrent-request']
        type: int
        description: Srv pool max concurrent request.
      srv_pool_max_request:
        aliases: ['srv-pool-max-request']
        type: int
        description: Srv pool max request.
      srv_pool_ttl:
        aliases: ['srv-pool-ttl']
        type: int
        description: Srv pool ttl.
      ssl_certificate:
        aliases: ['ssl-certificate']
        type: list
        elements: str
        description: Ssl certificate.
      ssl_max_version:
        aliases: ['ssl-max-version']
        type: str
        description: Ssl max version.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      ssl_min_version:
        aliases: ['ssl-min-version']
        type: str
        description: Ssl min version.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      status:
        type: str
        description: Status.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LLM Proxy.
      fortinet.fmgdevice.fmgd_llm_proxy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        llm_proxy:
          # hostname: <list or string>
          # incoming_http_port: <integer>
          # incoming_https_port: <integer>
          # incoming_ip: <string>
          # incoming_ip6: <string>
          # interface: <list or string>
          # ipv6_status: <value in [disable, enable]>
          # name: <string>
          # protocol: ["http", "https"]
          # srv_pool_max_concurrent_request: <integer>
          # srv_pool_max_request: <integer>
          # srv_pool_ttl: <integer>
          # ssl_certificate: <list or string>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/llm/proxy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'llm_proxy': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'hostname': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'incoming-http-port': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'incoming-https-port': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'incoming-ip': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'incoming-ip6': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'interface': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.6.5', '']], 'type': 'list', 'choices': ['http', 'https'], 'elements': 'str'},
                'srv-pool-max-concurrent-request': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'srv-pool-max-request': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'srv-pool-ttl': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'ssl-certificate': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'ssl-max-version': {'v_range': [['7.6.5', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.6.5', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'llm_proxy'),
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
