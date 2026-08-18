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
module: fmgd_firewall_interfacepolicy6
short_description: Configure IPv6 interface policies.
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
  firewall_interfacepolicy6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      address_type:
        aliases: ['address-type']
        type: str
        description: Address type.
        choices: ['ipv4', 'ipv6']
      application_list:
        aliases: ['application-list']
        type: list
        elements: str
        description: Application list name.
      application_list_status:
        aliases: ['application-list-status']
        type: str
        description: Enable/disable application control.
        choices: ['disable', 'enable']
      av_profile:
        aliases: ['av-profile']
        type: list
        elements: str
        description: Antivirus profile.
      av_profile_status:
        aliases: ['av-profile-status']
        type: str
        description: Enable/disable antivirus.
        choices: ['disable', 'enable']
      casb_profile:
        aliases: ['casb-profile']
        type: list
        elements: str
        description: CASB profile.
      casb_profile_status:
        aliases: ['casb-profile-status']
        type: str
        description: Enable/disable CASB.
        choices: ['disable', 'enable']
      comments:
        type: str
        description: Comments.
      dlp_profile:
        aliases: ['dlp-profile']
        type: list
        elements: str
        description: DLP profile name.
      dlp_profile_status:
        aliases: ['dlp-profile-status']
        type: str
        description: Enable/disable DLP.
        choices: ['disable', 'enable']
      dsri:
        type: str
        description: Enable/disable DSRI.
        choices: ['disable', 'enable']
      dstaddr6:
        type: list
        elements: str
        description: IPv6 address object to limit traffic monitoring to network traffic sent to the specified address or range.
      emailfilter_profile:
        aliases: ['emailfilter-profile']
        type: list
        elements: str
        description: Email filter profile.
      emailfilter_profile_status:
        aliases: ['emailfilter-profile-status']
        type: str
        description: Enable/disable email filter.
        choices: ['disable', 'enable']
      interface:
        type: list
        elements: str
        description: Monitored interface name from available interfaces.
      ips_sensor:
        aliases: ['ips-sensor']
        type: list
        elements: str
        description: IPS sensor name.
      ips_sensor_status:
        aliases: ['ips-sensor-status']
        type: str
        description: Enable/disable IPS.
        choices: ['disable', 'enable']
      label:
        type: str
        description: Label.
      logtraffic:
        type: str
        description: Logging type to be used in this policy
        choices: ['disable', 'all', 'utm']
      policyid:
        type: int
        description: Policy ID
        required: true
      service6:
        type: list
        elements: str
        description: Service name.
      srcaddr6:
        type: list
        elements: str
        description: IPv6 address object to limit traffic monitoring to network traffic sent from the specified address or range.
      status:
        type: str
        description: Enable/disable this policy.
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
      webfilter_profile:
        aliases: ['webfilter-profile']
        type: list
        elements: str
        description: Web filter profile.
      webfilter_profile_status:
        aliases: ['webfilter-profile-status']
        type: str
        description: Enable/disable web filtering.
        choices: ['disable', 'enable']
      dlp_sensor_status:
        aliases: ['dlp-sensor-status']
        type: str
        description: Enable/disable DLP.
        choices: ['disable', 'enable']
      dlp_sensor:
        aliases: ['dlp-sensor']
        type: list
        elements: str
        description: DLP sensor name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 interface policies.
      fortinet.fmgdevice.fmgd_firewall_interfacepolicy6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_interfacepolicy6:
          policyid: 0 # Required variable, integer
          # address_type: <value in [ipv4, ipv6]>
          # application_list: <list or string>
          # application_list_status: <value in [disable, enable]>
          # av_profile: <list or string>
          # av_profile_status: <value in [disable, enable]>
          # casb_profile: <list or string>
          # casb_profile_status: <value in [disable, enable]>
          # comments: <string>
          # dlp_profile: <list or string>
          # dlp_profile_status: <value in [disable, enable]>
          # dsri: <value in [disable, enable]>
          # dstaddr6: <list or string>
          # emailfilter_profile: <list or string>
          # emailfilter_profile_status: <value in [disable, enable]>
          # interface: <list or string>
          # ips_sensor: <list or string>
          # ips_sensor_status: <value in [disable, enable]>
          # label: <string>
          # logtraffic: <value in [disable, all, utm]>
          # service6: <list or string>
          # srcaddr6: <list or string>
          # status: <value in [disable, enable]>
          # uuid: <string>
          # webfilter_profile: <list or string>
          # webfilter_profile_status: <value in [disable, enable]>
          # dlp_sensor_status: <value in [disable, enable]>
          # dlp_sensor: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/interface-policy6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_interfacepolicy6': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'address-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'application-list': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'application-list-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'av-profile-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'casb-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'casb-profile-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dlp-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-profile-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dsri': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'emailfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'emailfilter-profile-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ips-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ips-sensor-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'label': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'logtraffic': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'service6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'webfilter-profile-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-sensor-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_interfacepolicy6'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
