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
module: fmgd_firewall_localinpolicy6
short_description: Configure user defined IPv6 local-in policies.
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
  firewall_localinpolicy6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Action performed on traffic matching the policy
        choices: ['deny', 'accept']
      comments:
        type: str
        description: Comment.
      dstaddr:
        type: list
        elements: str
        description: Destination address object from available options.
      dstaddr_negate:
        aliases: ['dstaddr-negate']
        type: str
        description: When enabled dstaddr specifies what the destination address must NOT be.
        choices: ['disable', 'enable']
      internet_service6_src:
        aliases: ['internet-service6-src']
        type: str
        description: Enable/disable use of IPv6 Internet Services in source for this local-in policy.
        choices: ['disable', 'enable']
      internet_service6_src_custom:
        aliases: ['internet-service6-src-custom']
        type: list
        elements: str
        description: Custom IPv6 Internet Service source name.
      internet_service6_src_custom_group:
        aliases: ['internet-service6-src-custom-group']
        type: list
        elements: str
        description: Custom Internet Service6 source group name.
      internet_service6_src_group:
        aliases: ['internet-service6-src-group']
        type: list
        elements: str
        description: Internet Service6 source group name.
      internet_service6_src_name:
        aliases: ['internet-service6-src-name']
        type: list
        elements: str
        description: IPv6 Internet Service source name.
      internet_service6_src_negate:
        aliases: ['internet-service6-src-negate']
        type: str
        description: When enabled internet-service6-src specifies what the service must NOT be.
        choices: ['disable', 'enable']
      intf:
        type: list
        elements: str
        description: Incoming interface name from available options.
      policyid:
        type: int
        description: User defined local in policy ID.
        required: true
      schedule:
        type: list
        elements: str
        description: Schedule object from available options.
      service:
        type: list
        elements: str
        description: Service object from available options.
      service_negate:
        aliases: ['service-negate']
        type: str
        description: When enabled service specifies what the service must NOT be.
        choices: ['disable', 'enable']
      srcaddr:
        type: list
        elements: str
        description: Source address object from available options.
      srcaddr_negate:
        aliases: ['srcaddr-negate']
        type: str
        description: When enabled srcaddr specifies what the source address must NOT be.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable this local-in policy.
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
      virtual_patch:
        aliases: ['virtual-patch']
        type: str
        description: Enable/disable the virtual patching feature.
        choices: ['disable', 'enable']
      internet_service6_src_fortiguard:
        aliases: ['internet-service6-src-fortiguard']
        type: list
        elements: str
        description: FortiGuard IPv6 Internet Service source name.
      logtraffic:
        type: str
        description: Enable/disable local-in traffic logging.
        choices: ['disable', 'enable']
      _policy_block:
        type: int
        description: Assigned policy block.
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure user defined IPv6 local-in policies.
      fortinet.fmgdevice.fmgd_firewall_localinpolicy6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_localinpolicy6:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # comments: <string>
          # dstaddr: <list or string>
          # dstaddr_negate: <value in [disable, enable]>
          # internet_service6_src: <value in [disable, enable]>
          # internet_service6_src_custom: <list or string>
          # internet_service6_src_custom_group: <list or string>
          # internet_service6_src_group: <list or string>
          # internet_service6_src_name: <list or string>
          # internet_service6_src_negate: <value in [disable, enable]>
          # intf: <list or string>
          # schedule: <list or string>
          # service: <list or string>
          # service_negate: <value in [disable, enable]>
          # srcaddr: <list or string>
          # srcaddr_negate: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # uuid: <string>
          # virtual_patch: <value in [disable, enable]>
          # internet_service6_src_fortiguard: <list or string>
          # logtraffic: <value in [disable, enable]>
          # _policy_block: <integer>
          # custom_tags: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_localinpolicy6': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr-negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-custom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-custom-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'schedule': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service-negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr-negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'virtual-patch': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logtraffic': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_policy_block': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_localinpolicy6'),
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
