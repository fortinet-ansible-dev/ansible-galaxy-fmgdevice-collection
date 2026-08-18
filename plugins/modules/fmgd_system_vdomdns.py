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
module: fmgd_system_vdomdns
short_description: Configure DNS servers for a non-management VDOM.
version_added: "1.0.0"
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
  system_vdomdns:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      alt_primary:
        aliases: ['alt-primary']
        type: str
        description: Alternate primary DNS server.
      alt_secondary:
        aliases: ['alt-secondary']
        type: str
        description: Alternate secondary DNS server.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      ip6_primary:
        aliases: ['ip6-primary']
        type: str
        description: Primary IPv6 DNS server IP address for the VDOM.
      ip6_secondary:
        aliases: ['ip6-secondary']
        type: str
        description: Secondary IPv6 DNS server IP address for the VDOM.
      primary:
        type: str
        description: Primary DNS server IP address for the VDOM.
      protocol:
        type: list
        elements: str
        description: DNS transport protocols.
        choices: ['cleartext', 'dot', 'doh']
      secondary:
        type: str
        description: Secondary DNS server IP address for the VDOM.
      server_hostname:
        aliases: ['server-hostname']
        type: list
        elements: str
        description: DNS server host name list.
      server_select_method:
        aliases: ['server-select-method']
        type: str
        description: Specify how configured servers are prioritized.
        choices: ['least-rtt', 'failover']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP for communications with the DNS server.
      ssl_certificate:
        aliases: ['ssl-certificate']
        type: list
        elements: str
        description: Name of local certificate for SSL connections.
      vdom_dns:
        aliases: ['vdom-dns']
        type: str
        description: Enable/disable configuring DNS servers for the current VDOM.
        choices: ['disable', 'enable']
      dns_over_tls:
        aliases: ['dns-over-tls']
        type: str
        description: Enable/disable/enforce DNS over TLS.
        choices: ['disable', 'enable', 'enforce']
      source_ip_interface:
        aliases: ['source-ip-interface']
        type: list
        elements: str
        description: IP address of the specified interface as the source IP address.
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DNS servers for a non-management VDOM.
      fortinet.fmgdevice.fmgd_system_vdomdns:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        system_vdomdns:
          # alt_primary: <string>
          # alt_secondary: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ip6_primary: <string>
          # ip6_secondary: <string>
          # primary: <string>
          # protocol: ["cleartext", "dot", "doh"]
          # secondary: <string>
          # server_hostname: <list or string>
          # server_select_method: <value in [least-rtt, failover]>
          # source_ip: <string>
          # ssl_certificate: <list or string>
          # vdom_dns: <value in [disable, enable]>
          # dns_over_tls: <value in [disable, enable, enforce]>
          # source_ip_interface: <list or string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/vdom-dns'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_vdomdns': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'alt-primary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'alt-secondary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ip6-primary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ip6-secondary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'primary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'choices': ['cleartext', 'dot', 'doh'], 'elements': 'str'},
                'secondary': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'server-hostname': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['least-rtt', 'failover'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vdom-dns': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-over-tls': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable', 'enforce'], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vdomdns'),
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
