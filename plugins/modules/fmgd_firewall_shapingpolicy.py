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
module: fmgd_firewall_shapingpolicy
short_description: Configure shaping policies.
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
  firewall_shapingpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      app_category:
        aliases: ['app-category']
        type: list
        elements: str
        description: IDs of one or more application categories that this shaper applies application control traffic shaping to.
      app_group:
        aliases: ['app-group']
        type: list
        elements: str
        description: One or more application group names.
      application:
        type: list
        elements: int
        description: IDs of one or more applications that this shaper applies application control traffic shaping to.
      class_id:
        aliases: ['class-id']
        type: int
        description: Traffic class ID.
      class_id_reverse:
        aliases: ['class-id-reverse']
        type: int
        description: Reverse class id.
      comment:
        type: str
        description: Comments.
      diffserv_forward:
        aliases: ['diffserv-forward']
        type: str
        description: Enable to change packets DiffServ values to the specified diffservcode-forward value.
        choices: ['disable', 'enable']
      diffserv_reverse:
        aliases: ['diffserv-reverse']
        type: str
        description: Enable to change packets reverse
        choices: ['disable', 'enable']
      diffservcode_forward:
        aliases: ['diffservcode-forward']
        type: str
        description: Change packets DiffServ to this value.
      diffservcode_rev:
        aliases: ['diffservcode-rev']
        type: str
        description: Change packets reverse
      dstaddr:
        type: list
        elements: str
        description: IPv4 destination address and address group names.
      dstaddr6:
        type: list
        elements: str
        description: IPv6 destination address and address group names.
      dstintf:
        type: list
        elements: str
        description: One or more outgoing
      groups:
        type: list
        elements: str
        description: Apply this traffic shaping policy to user groups that have authenticated with the FortiGate.
      http_response_match:
        aliases: ['http-response-match']
        type: str
        description: Http response match.
        choices: ['disable', 'enable']
      id:
        type: int
        description: Shaping policy ID
        required: true
      internet_service_custom:
        aliases: ['internet-service-custom']
        type: list
        elements: str
        description: Custom Internet Service name.
      internet_service_custom_group:
        aliases: ['internet-service-custom-group']
        type: list
        elements: str
        description: Custom Internet Service group name.
      internet_service_group:
        aliases: ['internet-service-group']
        type: list
        elements: str
        description: Internet Service group name.
      internet_service_name:
        aliases: ['internet-service-name']
        type: list
        elements: str
        description: Internet Service ID.
      ip_version:
        aliases: ['ip-version']
        type: str
        description: Apply this traffic shaping policy to IPv4 or IPv6 traffic.
        choices: ['4', '6']
      name:
        type: str
        description: Shaping policy name.
      per_ip_shaper:
        aliases: ['per-ip-shaper']
        type: list
        elements: str
        description: Per-IP traffic shaper to apply with this policy.
      schedule:
        type: list
        elements: str
        description: Schedule name.
      service:
        type: list
        elements: str
        description: Service and service group names.
      service_type:
        aliases: ['service-type']
        type: str
        description: Select service-type
        choices: ['service', 'internet-service']
      srcaddr:
        type: list
        elements: str
        description: IPv4 source address and address group names.
      srcaddr6:
        type: list
        elements: str
        description: IPv6 source address and address group names.
      status:
        type: str
        description: Enable/disable this traffic shaping policy.
        choices: ['disable', 'enable']
      traffic_shaper:
        aliases: ['traffic-shaper']
        type: list
        elements: str
        description: Traffic shaper to apply to traffic forwarded by the firewall policy.
      traffic_shaper_reverse:
        aliases: ['traffic-shaper-reverse']
        type: list
        elements: str
        description: Traffic shaper to apply to response traffic received by the firewall policy.
      users:
        type: list
        elements: str
        description: Apply this traffic shaping policy to individual users that have authenticated with the FortiGate.
      uuid:
        type: str
        description: Universally Unique Identifier
      traffic_type:
        aliases: ['traffic-type']
        type: str
        description: Traffic type.
        choices: ['forwarding', 'local-in', 'local-out']
      tos_mask:
        aliases: ['tos-mask']
        type: str
        description: Non-zero bit positions are used for comparison while zero bit positions are ignored.
      srcintf:
        type: list
        elements: str
        description: One or more incoming
      cos:
        type: str
        description: VLAN CoS bit pattern.
      internet_service_src:
        aliases: ['internet-service-src']
        type: str
        description: Enable/disable use of Internet Services in source for this policy.
        choices: ['disable', 'enable']
      internet_service:
        aliases: ['internet-service']
        type: str
        description: Enable/disable use of Internet Services for this policy.
        choices: ['enable', 'disable']
      internet_service_src_custom:
        aliases: ['internet-service-src-custom']
        type: list
        elements: str
        description: Custom Internet Service source name.
      tos_negate:
        aliases: ['tos-negate']
        type: str
        description: Enable negated TOS match.
        choices: ['disable', 'enable']
      internet_service_src_name:
        aliases: ['internet-service-src-name']
        type: list
        elements: str
        description: Internet Service source name.
      internet_service_src_custom_group:
        aliases: ['internet-service-src-custom-group']
        type: list
        elements: str
        description: Custom Internet Service source group name.
      cos_mask:
        aliases: ['cos-mask']
        type: str
        description: VLAN CoS evaluated bits.
      internet_service_src_group:
        aliases: ['internet-service-src-group']
        type: list
        elements: str
        description: Internet Service source group name.
      url_category:
        aliases: ['url-category']
        type: list
        elements: str
        description: IDs of one or more FortiGuard Web Filtering categories that this shaper applies traffic shaping to.
      tos:
        type: str
        description: ToS
      internet_service_id:
        aliases: ['internet-service-id']
        type: list
        elements: str
        description: Internet Service ID.
      internet_service_src_id:
        aliases: ['internet-service-src-id']
        type: list
        elements: str
        description: Internet Service source ID.
      internet_service_src_fortiguard:
        aliases: ['internet-service-src-fortiguard']
        type: list
        elements: str
        description: FortiGuard Internet Service source name.
      internet_service_fortiguard:
        aliases: ['internet-service-fortiguard']
        type: list
        elements: str
        description: FortiGuard Internet Service name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure shaping policies.
      fortinet.fmgdevice.fmgd_firewall_shapingpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_shapingpolicy:
          id: 0 # Required variable, integer
          # app_category: <list or string>
          # app_group: <list or string>
          # application: <list or integer>
          # class_id: <integer>
          # class_id_reverse: <integer>
          # comment: <string>
          # diffserv_forward: <value in [disable, enable]>
          # diffserv_reverse: <value in [disable, enable]>
          # diffservcode_forward: <string>
          # diffservcode_rev: <string>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # dstintf: <list or string>
          # groups: <list or string>
          # http_response_match: <value in [disable, enable]>
          # internet_service_custom: <list or string>
          # internet_service_custom_group: <list or string>
          # internet_service_group: <list or string>
          # internet_service_name: <list or string>
          # ip_version: <value in [4, 6]>
          # name: <string>
          # per_ip_shaper: <list or string>
          # schedule: <list or string>
          # service: <list or string>
          # service_type: <value in [service, internet-service]>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # status: <value in [disable, enable]>
          # traffic_shaper: <list or string>
          # traffic_shaper_reverse: <list or string>
          # users: <list or string>
          # uuid: <string>
          # traffic_type: <value in [forwarding, local-in, local-out]>
          # tos_mask: <string>
          # srcintf: <list or string>
          # cos: <string>
          # internet_service_src: <value in [disable, enable]>
          # internet_service: <value in [enable, disable]>
          # internet_service_src_custom: <list or string>
          # tos_negate: <value in [disable, enable]>
          # internet_service_src_name: <list or string>
          # internet_service_src_custom_group: <list or string>
          # cos_mask: <string>
          # internet_service_src_group: <list or string>
          # url_category: <list or string>
          # tos: <string>
          # internet_service_id: <list or string>
          # internet_service_src_id: <list or string>
          # internet_service_src_fortiguard: <list or string>
          # internet_service_fortiguard: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_shapingpolicy': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'app-category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'app-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'application': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'class-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'class-id-reverse': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'diffserv-forward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'groups': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'http-response-match': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'internet-service-custom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-custom-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ip-version': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['4', '6'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'per-ip-shaper': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'schedule': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['service', 'internet-service'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'traffic-shaper-reverse': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'users': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'traffic-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['forwarding', 'local-in', 'local-out'], 'type': 'str'},
                'tos-mask': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'srcintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cos': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'internet-service-src': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'tos-negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-custom-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cos-mask': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'internet-service-src-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'url-category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'tos': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'internet-service-id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shapingpolicy'),
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
