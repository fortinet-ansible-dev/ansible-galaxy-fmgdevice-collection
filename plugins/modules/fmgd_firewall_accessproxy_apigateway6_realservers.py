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
module: fmgd_firewall_accessproxy_apigateway6_realservers
short_description: Select the real servers that this Access Proxy will distribute traffic to.
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
  access-proxy:
    description: Deprecated, please use "access_proxy"
    type: str
  access_proxy:
    description: The parameter (access-proxy) in requested url.
    type: str
  api-gateway6:
    description: Deprecated, please use "api_gateway6"
    type: str
  api_gateway6:
    description: The parameter (api-gateway6) in requested url.
    type: str
  firewall_accessproxy_apigateway6_realservers:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_type:
        aliases: ['addr-type']
        type: str
        description: Type of address.
        choices: ['fqdn', 'ip']
      address:
        type: list
        elements: str
        description: Address or address group of the real server.
      domain:
        type: str
        description: Wildcard domain name of the real server.
      health_check:
        aliases: ['health-check']
        type: str
        description: Enable to check the responsiveness of the real server before forwarding traffic.
        choices: ['disable', 'enable']
      health_check_proto:
        aliases: ['health-check-proto']
        type: str
        description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
        choices: ['ping', 'http', 'tcp-connect']
      holddown_interval:
        aliases: ['holddown-interval']
        type: str
        description: Enable/disable holddown timer.
        choices: ['disable', 'enable']
      http_host:
        aliases: ['http-host']
        type: str
        description: HTTP server domain name in HTTP header.
      id:
        type: int
        description: Real server ID.
        required: true
      ip:
        type: str
        description: IPv6 address of the real server.
      mappedport:
        type: list
        elements: str
        description: Port for communicating with the real server.
      port:
        type: int
        description: Port for communicating with the real server.
      ssh_client_cert:
        aliases: ['ssh-client-cert']
        type: list
        elements: str
        description: Set access-proxy SSH client certificate profile.
      ssh_host_key:
        aliases: ['ssh-host-key']
        type: list
        elements: str
        description: One or more server host key.
      ssh_host_key_validation:
        aliases: ['ssh-host-key-validation']
        type: str
        description: Enable/disable SSH real server host key validation.
        choices: ['disable', 'enable']
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
        description: TCP forwarding server type.
        choices: ['tcp-forwarding', 'ssh']
      verify_cert:
        aliases: ['verify-cert']
        type: str
        description: Enable/disable certificate verification of the real server.
        choices: ['disable', 'enable']
      weight:
        type: int
        description: Weight of the real server.
      external_auth:
        aliases: ['external-auth']
        type: str
        description: Enable/disable use of external browser as user-agent for SAML user authentication.
        choices: ['disable', 'enable']
      tunnel_encryption:
        aliases: ['tunnel-encryption']
        type: str
        description: Tunnel encryption.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Select the real servers that this Access Proxy will distribute traffic to.
      fortinet.fmgdevice.fmgd_firewall_accessproxy_apigateway6_realservers:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        access_proxy: <your own value>
        api_gateway6: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxy_apigateway6_realservers:
          id: 0 # Required variable, integer
          # addr_type: <value in [fqdn, ip]>
          # address: <list or string>
          # domain: <string>
          # health_check: <value in [disable, enable]>
          # health_check_proto: <value in [ping, http, tcp-connect]>
          # holddown_interval: <value in [disable, enable]>
          # http_host: <string>
          # ip: <string>
          # mappedport: <list or string>
          # port: <integer>
          # ssh_client_cert: <list or string>
          # ssh_host_key: <list or string>
          # ssh_host_key_validation: <value in [disable, enable]>
          # status: <value in [active, standby, disable]>
          # translate_host: <value in [disable, enable]>
          # type: <value in [tcp-forwarding, ssh]>
          # verify_cert: <value in [disable, enable]>
          # weight: <integer>
          # external_auth: <value in [disable, enable]>
          # tunnel_encryption: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'access-proxy': {'type': 'str', 'api_name': 'access_proxy'},
        'access_proxy': {'type': 'str'},
        'api-gateway6': {'type': 'str', 'api_name': 'api_gateway6'},
        'api_gateway6': {'type': 'str'},
        'firewall_accessproxy_apigateway6_realservers': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'addr-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'health-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'health-check-proto': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                'holddown-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'mappedport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssh-client-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssh-host-key': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ssh-host-key-validation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'translate-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                'verify-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'weight': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'external-auth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-encryption': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy_apigateway6_realservers'),
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
