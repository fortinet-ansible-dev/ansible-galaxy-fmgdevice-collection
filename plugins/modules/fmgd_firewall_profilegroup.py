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
module: fmgd_firewall_profilegroup
short_description: Configure profile groups.
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
  firewall_profilegroup:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      application_list:
        aliases: ['application-list']
        type: list
        elements: str
        description: Name of an existing Application list.
      av_profile:
        aliases: ['av-profile']
        type: list
        elements: str
        description: Name of an existing Antivirus profile.
      casb_profile:
        aliases: ['casb-profile']
        type: list
        elements: str
        description: Name of an existing CASB profile.
      dlp_profile:
        aliases: ['dlp-profile']
        type: list
        elements: str
        description: Name of an existing DLP profile.
      dnsfilter_profile:
        aliases: ['dnsfilter-profile']
        type: list
        elements: str
        description: Name of an existing DNS filter profile.
      emailfilter_profile:
        aliases: ['emailfilter-profile']
        type: list
        elements: str
        description: Name of an existing email filter profile.
      file_filter_profile:
        aliases: ['file-filter-profile']
        type: list
        elements: str
        description: Name of an existing file-filter profile.
      ia_profile:
        aliases: ['ia-profile']
        type: list
        elements: str
        description: Image analyzer profile.
      icap_profile:
        aliases: ['icap-profile']
        type: list
        elements: str
        description: Name of an existing ICAP profile.
      ips_sensor:
        aliases: ['ips-sensor']
        type: list
        elements: str
        description: Name of an existing IPS sensor.
      isolator_profile:
        aliases: ['isolator-profile']
        type: list
        elements: str
        description: Isolator profile.
      name:
        type: str
        description: Profile group name.
        required: true
      profile_protocol_options:
        aliases: ['profile-protocol-options']
        type: list
        elements: str
        description: Name of an existing Protocol options profile.
      redirect_profile:
        aliases: ['redirect-profile']
        type: list
        elements: str
        description: Redirect profile.
      ssh_filter_profile:
        aliases: ['ssh-filter-profile']
        type: list
        elements: str
        description: Name of an existing SSH filter profile.
      ssl_ssh_profile:
        aliases: ['ssl-ssh-profile']
        type: list
        elements: str
        description: Name of an existing SSL SSH profile.
      videofilter_profile:
        aliases: ['videofilter-profile']
        type: list
        elements: str
        description: Name of an existing VideoFilter profile.
      webfilter_profile:
        aliases: ['webfilter-profile']
        type: list
        elements: str
        description: Name of an existing Web filter profile.
      virtual_patch_profile:
        aliases: ['virtual-patch-profile']
        type: list
        elements: str
        description: Name of an existing virtual-patch profile.
      diameter_filter_profile:
        aliases: ['diameter-filter-profile']
        type: list
        elements: str
        description: Name of an existing Diameter filter profile.
      voip_profile:
        aliases: ['voip-profile']
        type: list
        elements: str
        description: Name of an existing VoIP
      ips_voip_filter:
        aliases: ['ips-voip-filter']
        type: list
        elements: str
        description: Name of an existing VoIP
      waf_profile:
        aliases: ['waf-profile']
        type: list
        elements: str
        description: Name of an existing Web application firewall profile.
      sctp_filter_profile:
        aliases: ['sctp-filter-profile']
        type: list
        elements: str
        description: Name of an existing SCTP filter profile.
      dlp_sensor:
        aliases: ['dlp-sensor']
        type: list
        elements: str
        description: Name of an existing DLP sensor.
      cifs_profile:
        aliases: ['cifs-profile']
        type: list
        elements: str
        description: Name of an existing CIFS profile.
      mms_profile:
        aliases: ['mms-profile']
        type: list
        elements: str
        description: Name of an existing MMS profile.
      spamfilter_profile:
        aliases: ['spamfilter-profile']
        type: list
        elements: str
        description: Name of an existing Spam filter profile.
      telemetry_profile:
        aliases: ['telemetry-profile']
        type: list
        elements: str
        description: Name of an existing telemetry profile.
      llm_profile:
        aliases: ['llm-profile']
        type: list
        elements: str
        description: Llm profile.
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure profile groups.
      fortinet.fmgdevice.fmgd_firewall_profilegroup:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_profilegroup:
          name: "your value" # Required variable, string
          # application_list: <list or string>
          # av_profile: <list or string>
          # casb_profile: <list or string>
          # dlp_profile: <list or string>
          # dnsfilter_profile: <list or string>
          # emailfilter_profile: <list or string>
          # file_filter_profile: <list or string>
          # ia_profile: <list or string>
          # icap_profile: <list or string>
          # ips_sensor: <list or string>
          # isolator_profile: <list or string>
          # profile_protocol_options: <list or string>
          # redirect_profile: <list or string>
          # ssh_filter_profile: <list or string>
          # ssl_ssh_profile: <list or string>
          # videofilter_profile: <list or string>
          # webfilter_profile: <list or string>
          # virtual_patch_profile: <list or string>
          # diameter_filter_profile: <list or string>
          # voip_profile: <list or string>
          # ips_voip_filter: <list or string>
          # waf_profile: <list or string>
          # sctp_filter_profile: <list or string>
          # dlp_sensor: <list or string>
          # cifs_profile: <list or string>
          # mms_profile: <list or string>
          # spamfilter_profile: <list or string>
          # telemetry_profile: <list or string>
          # llm_profile: <list or string>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-group'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_profilegroup': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'application-list': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'av-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'casb-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dnsfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'emailfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'file-filter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ia-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'icap-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ips-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'isolator-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'profile-protocol-options': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'redirect-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssh-filter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-ssh-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'videofilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'webfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'voip-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ips-voip-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'waf-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sctp-filter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cifs-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'mms-profile': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'spamfilter-profile': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'telemetry-profile': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'llm-profile': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profilegroup'),
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
