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
module: fmgd_log_eventfilter
short_description: Configure log event filters.
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
  log_eventfilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      cifs:
        type: str
        description: Enable/disable CIFS logging.
        choices: ['disable', 'enable']
      connector:
        type: str
        description: Enable/disable SDN connector logging.
        choices: ['disable', 'enable']
      endpoint:
        type: str
        description: Enable/disable endpoint event logging.
        choices: ['disable', 'enable']
      event:
        type: str
        description: Enable/disable event logging.
        choices: ['disable', 'enable']
      fortiextender:
        type: str
        description: Enable/disable FortiExtender logging.
        choices: ['disable', 'enable']
      ha:
        type: str
        description: Enable/disable ha event logging.
        choices: ['disable', 'enable']
      rest_api:
        aliases: ['rest-api']
        type: str
        description: Enable/disable REST API logging.
        choices: ['disable', 'enable']
      router:
        type: str
        description: Enable/disable router event logging.
        choices: ['disable', 'enable']
      sdwan:
        type: str
        description: Enable/disable SD-WAN logging.
        choices: ['disable', 'enable']
      security_rating:
        aliases: ['security-rating']
        type: str
        description: Enable/disable Security Rating result logging.
        choices: ['disable', 'enable']
      switch_controller:
        aliases: ['switch-controller']
        type: str
        description: Enable/disable Switch-Controller logging.
        choices: ['disable', 'enable']
      system:
        type: str
        description: Enable/disable system event logging.
        choices: ['disable', 'enable']
      user:
        type: str
        description: Enable/disable user authentication event logging.
        choices: ['disable', 'enable']
      vpn:
        type: str
        description: Enable/disable VPN event logging.
        choices: ['disable', 'enable']
      wan_opt:
        aliases: ['wan-opt']
        type: str
        description: Enable/disable WAN optimization event logging.
        choices: ['disable', 'enable']
      webproxy:
        type: str
        description: Enable/disable web proxy event logging.
        choices: ['disable', 'enable']
      wireless_activity:
        aliases: ['wireless-activity']
        type: str
        description: Enable/disable wireless event logging.
        choices: ['disable', 'enable']
      aggd:
        type: str
        description: Enable/disable log for aggd events.
        choices: ['disable', 'enable']
      crwl:
        type: str
        description: Enable/disable log for crwl events.
        choices: ['disable', 'enable']
      iptables:
        type: str
        description: Iptables.
        choices: ['disable', 'enable']
      wcs:
        type: str
        description: Enable/disable log for wcs events.
        choices: ['disable', 'enable']
      wdb:
        type: str
        description: Enable/disable log for wdb events.
        choices: ['disable', 'enable']
      security_audit:
        aliases: ['security-audit']
        type: str
        description: Enable/disable Security Fabric audit result logging.
        choices: ['disable', 'enable']
      compliance_check:
        aliases: ['compliance-check']
        type: str
        description: Enable/disable PCI DSS compliance check logging.
        choices: ['disable', 'enable']
      telemetry:
        type: str
        description: Enable/disable telemetry event logging.
        choices: ['disable', 'enable']
      web_svc:
        aliases: ['web-svc']
        type: str
        description: Enable/disable web-svc performance logging.
        choices: ['disable', 'enable']
      nftables:
        type: str
        description: Nftables.
        choices: ['disable', 'enable']
      ftnt_sec_mod:
        aliases: ['ftnt-sec-mod']
        type: str
        description: Enable/disable Forti Security Module logging.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure log event filters.
      fortinet.fmgdevice.fmgd_log_eventfilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        log_eventfilter:
          # cifs: <value in [disable, enable]>
          # connector: <value in [disable, enable]>
          # endpoint: <value in [disable, enable]>
          # event: <value in [disable, enable]>
          # fortiextender: <value in [disable, enable]>
          # ha: <value in [disable, enable]>
          # rest_api: <value in [disable, enable]>
          # router: <value in [disable, enable]>
          # sdwan: <value in [disable, enable]>
          # security_rating: <value in [disable, enable]>
          # switch_controller: <value in [disable, enable]>
          # system: <value in [disable, enable]>
          # user: <value in [disable, enable]>
          # vpn: <value in [disable, enable]>
          # wan_opt: <value in [disable, enable]>
          # webproxy: <value in [disable, enable]>
          # wireless_activity: <value in [disable, enable]>
          # aggd: <value in [disable, enable]>
          # crwl: <value in [disable, enable]>
          # iptables: <value in [disable, enable]>
          # wcs: <value in [disable, enable]>
          # wdb: <value in [disable, enable]>
          # security_audit: <value in [disable, enable]>
          # compliance_check: <value in [disable, enable]>
          # telemetry: <value in [disable, enable]>
          # web_svc: <value in [disable, enable]>
          # nftables: <value in [disable, enable]>
          # ftnt_sec_mod: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/eventfilter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_eventfilter': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'cifs': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'connector': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'endpoint': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'event': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiextender': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rest-api': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'router': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sdwan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'security-rating': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-controller': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'system': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vpn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wan-opt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webproxy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wireless-activity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aggd': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'crwl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iptables': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wcs': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wdb': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'security-audit': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'compliance-check': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'telemetry': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-svc': {'v_range': [['7.4.9', '7.4.11'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nftables': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ftnt-sec-mod': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_eventfilter'),
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
