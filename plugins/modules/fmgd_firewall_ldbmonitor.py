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
module: fmgd_firewall_ldbmonitor
short_description: Configure server load balancing health monitors.
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
  firewall_ldbmonitor:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dns_match_ip:
        aliases: ['dns-match-ip']
        type: str
        description: Response IP expected from DNS server.
      dns_protocol:
        aliases: ['dns-protocol']
        type: str
        description: Select the protocol used by the DNS health check monitor to check the health of the server
        choices: ['udp', 'tcp']
      dns_request_domain:
        aliases: ['dns-request-domain']
        type: str
        description: Fully qualified domain name to resolve for the DNS probe.
      http_get:
        aliases: ['http-get']
        type: str
        description: Request URI used to send a GET request to check the health of an HTTP server.
      http_match:
        aliases: ['http-match']
        type: str
        description: String to match the value expected in response to an HTTP-GET request.
      http_max_redirects:
        aliases: ['http-max-redirects']
        type: int
        description: The maximum number of HTTP redirects to be allowed
      interval:
        type: int
        description: Time between health checks
      name:
        type: str
        description: Monitor name.
        required: true
      port:
        type: int
        description: Service port used to perform the health check.
      retry:
        type: int
        description: Number health check attempts before the server is considered down
      src_ip:
        aliases: ['src-ip']
        type: str
        description: Source IP for ldb-monitor.
      timeout:
        type: int
        description: Time to wait to receive response to a health check from a server.
      type:
        type: str
        description: Select the Monitor type used by the health check monitor to check the health of the server
        choices: ['ping', 'tcp', 'http', 'passive-sip', 'https', 'dns']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure server load balancing health monitors.
      fortinet.fmgdevice.fmgd_firewall_ldbmonitor:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_ldbmonitor:
          name: "your value" # Required variable, string
          # dns_match_ip: <string>
          # dns_protocol: <value in [udp, tcp]>
          # dns_request_domain: <string>
          # http_get: <string>
          # http_match: <string>
          # http_max_redirects: <integer>
          # interval: <integer>
          # port: <integer>
          # retry: <integer>
          # src_ip: <string>
          # timeout: <integer>
          # type: <value in [ping, tcp, http, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ldb-monitor'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_ldbmonitor': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'dns-match-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dns-protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                'dns-request-domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-get': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-match': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-max-redirects': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'retry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'src-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['ping', 'tcp', 'http', 'passive-sip', 'https', 'dns'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ldbmonitor'),
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
