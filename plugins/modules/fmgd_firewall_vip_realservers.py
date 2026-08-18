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
module: fmgd_firewall_vip_realservers
short_description: Select the real servers that this server load balancing VIP will distribute traffic to.
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
  vip:
    description: The parameter (vip) in requested url.
    type: str
    required: true
  firewall_vip_realservers:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      address:
        type: list
        elements: str
        description: Dynamic address of the real server.
      client_ip:
        aliases: ['client-ip']
        type: list
        elements: str
        description: Only clients in this IP range can connect to this real server.
      health_check_proto:
        aliases: ['health-check-proto']
        type: str
        description: Health check proto.
        choices: ['ping', 'http']
      healthcheck:
        type: str
        description: Enable to check the responsiveness of the real server before forwarding traffic.
        choices: ['disable', 'enable', 'vip']
      holddown_interval:
        aliases: ['holddown-interval']
        type: int
        description: Time in seconds that the system waits before re-activating a previously down active server in the active-standby mode.
      http_host:
        aliases: ['http-host']
        type: str
        description: HTTP server domain name in HTTP header.
      ip:
        type: str
        description: IP address of the real server.
      max_connections:
        aliases: ['max-connections']
        type: int
        description: Max number of active connections that can be directed to the real server.
      port:
        type: int
        description: Port for communicating with the real server.
      seq:
        type: int
        description: Seq.
      status:
        type: str
        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
        choices: ['active', 'standby', 'disable']
      translate_host:
        aliases: ['translate-host']
        type: str
        description: Enable/disable translation of hostname/IP from virtual server to real server.
        choices: ['disable', 'enable']
      type:
        type: str
        description: Type of address.
        choices: ['ip', 'address']
      verify_cert:
        aliases: ['verify-cert']
        type: str
        description: Enable/disable certificate verification of the real server.
        choices: ['disable', 'enable']
      weight:
        type: int
        description: Weight of the real server.
      monitor:
        type: list
        elements: str
        description: Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
      id:
        type: int
        description: Real server ID.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Select the real servers that this server load balancing VIP will distribute traffic to.
      fortinet.fmgdevice.fmgd_firewall_vip_realservers:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        vip: <your own value>
        state: present # <value in [present, absent]>
        firewall_vip_realservers:
          id: 0 # Required variable, integer
          # address: <list or string>
          # client_ip: <list or string>
          # health_check_proto: <value in [ping, http]>
          # healthcheck: <value in [disable, enable, vip]>
          # holddown_interval: <integer>
          # http_host: <string>
          # ip: <string>
          # max_connections: <integer>
          # port: <integer>
          # seq: <integer>
          # status: <value in [active, standby, disable]>
          # translate_host: <value in [disable, enable]>
          # type: <value in [ip, address]>
          # verify_cert: <value in [disable, enable]>
          # weight: <integer>
          # monitor: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/vip/{vip}/realservers'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vip': {'required': True, 'type': 'str'},
        'firewall_vip_realservers': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'health-check-proto': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ping', 'http'], 'type': 'str'},
                'healthcheck': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                'holddown-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'http-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'seq': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'translate-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ip', 'address'], 'type': 'str'},
                'verify-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'weight': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'monitor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip_realservers'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
