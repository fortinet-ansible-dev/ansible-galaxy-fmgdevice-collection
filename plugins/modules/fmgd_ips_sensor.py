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
module: fmgd_ips_sensor
short_description: Configure IPS sensor.
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
  ips_sensor:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      block_malicious_url:
        aliases: ['block-malicious-url']
        type: str
        description: Enable/disable malicious URL blocking.
        choices: ['disable', 'enable']
      comment:
        type: str
        description: Comment.
      entries:
        type: list
        elements: dict
        description: Entries.
        suboptions:
          action:
            type: str
            description: Action taken with traffic in which signatures are detected.
            choices: ['pass', 'block', 'reset', 'default']
          application:
            type: list
            elements: str
            description: Operating systems to be protected.
          cve:
            type: list
            elements: str
            description: List of CVE IDs of the signatures to add to the sensor.
          default_action:
            aliases: ['default-action']
            type: str
            description: Signature default action filter.
            choices: ['block', 'pass', 'all', 'drop']
          default_status:
            aliases: ['default-status']
            type: str
            description: Signature default status filter.
            choices: ['disable', 'enable', 'all']
          exempt_ip:
            aliases: ['exempt-ip']
            type: list
            elements: dict
            description: Exempt ip.
            suboptions:
              dst_ip:
                aliases: ['dst-ip']
                type: list
                elements: str
                description: Destination IP address and netmask
              id:
                type: int
                description: Exempt IP ID.
              src_ip:
                aliases: ['src-ip']
                type: list
                elements: str
                description: Source IP address and netmask
          id:
            type: int
            description: Rule ID in IPS database
          last_modified:
            aliases: ['last-modified']
            type: list
            elements: str
            description: Filter by signature last modified date.
          location:
            type: list
            elements: str
            description: Protect client or server traffic.
          log:
            type: str
            description: Enable/disable logging of signatures included in filter.
            choices: ['disable', 'enable']
          log_attack_context:
            aliases: ['log-attack-context']
            type: str
            description: Enable/disable logging of attack context
            choices: ['disable', 'enable']
          log_packet:
            aliases: ['log-packet']
            type: str
            description: Enable/disable packet logging.
            choices: ['disable', 'enable']
          os:
            type: list
            elements: str
            description: Operating systems to be protected.
          protocol:
            type: list
            elements: str
            description: Protocols to be examined.
          quarantine:
            type: str
            description: Quarantine method.
            choices: ['none', 'attacker']
          quarantine_expiry:
            aliases: ['quarantine-expiry']
            type: str
            description: Duration of quarantine.
          quarantine_log:
            aliases: ['quarantine-log']
            type: str
            description: Enable/disable quarantine logging.
            choices: ['disable', 'enable']
          rate_count:
            aliases: ['rate-count']
            type: int
            description: Count of the rate.
          rate_duration:
            aliases: ['rate-duration']
            type: int
            description: Duration
          rate_mode:
            aliases: ['rate-mode']
            type: str
            description: Rate limit mode.
            choices: ['periodical', 'continuous']
          rate_track:
            aliases: ['rate-track']
            type: str
            description: Track the packet protocol field.
            choices: ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain']
          rule:
            type: list
            elements: str
            description: Identifies the predefined or custom IPS signatures to add to the sensor.
          severity:
            type: list
            elements: str
            description: Relative severity of the signature, from info to critical.
          status:
            type: str
            description: Status of the signatures included in filter.
            choices: ['disable', 'enable', 'default']
          vuln_type:
            aliases: ['vuln-type']
            type: list
            elements: int
            description: List of signature vulnerability types to filter by.
          tags:
            type: list
            elements: str
            description: Assign a custom tag filter to the IPS sensor.
      extended_log:
        aliases: ['extended-log']
        type: str
        description: Enable/disable extended logging.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Sensor name.
        required: true
      replacemsg_group:
        aliases: ['replacemsg-group']
        type: list
        elements: str
        description: Replacement message group.
      scan_botnet_connections:
        aliases: ['scan-botnet-connections']
        type: str
        description: Block or monitor connections to Botnet servers, or disable Botnet scanning.
        choices: ['disable', 'block', 'monitor']
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
    - name: Configure IPS sensor.
      fortinet.fmgdevice.fmgd_ips_sensor:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        ips_sensor:
          name: "your value" # Required variable, string
          # block_malicious_url: <value in [disable, enable]>
          # comment: <string>
          # entries:
          #   - action: <value in [pass, block, reset, ...]>
          #     application: <list or string>
          #     cve: <list or string>
          #     default_action: <value in [block, pass, all, ...]>
          #     default_status: <value in [disable, enable, all]>
          #     exempt_ip:
          #       - dst_ip: <list or string>
          #         id: <integer>
          #         src_ip: <list or string>
          #     id: <integer>
          #     last_modified: <list or string>
          #     location: <list or string>
          #     log: <value in [disable, enable]>
          #     log_attack_context: <value in [disable, enable]>
          #     log_packet: <value in [disable, enable]>
          #     os: <list or string>
          #     protocol: <list or string>
          #     quarantine: <value in [none, attacker]>
          #     quarantine_expiry: <string>
          #     quarantine_log: <value in [disable, enable]>
          #     rate_count: <integer>
          #     rate_duration: <integer>
          #     rate_mode: <value in [periodical, continuous]>
          #     rate_track: <value in [none, src-ip, dest-ip, ...]>
          #     rule: <list or string>
          #     severity: <list or string>
          #     status: <value in [disable, enable, default]>
          #     vuln_type: <list or integer>
          #     tags: <list or string>
          # extended_log: <value in [disable, enable]>
          # replacemsg_group: <list or string>
          # scan_botnet_connections: <value in [disable, block, monitor]>
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
        '/pm/config/device/{device}/vdom/{vdom}/ips/sensor'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ips_sensor': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'block-malicious-url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'entries': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['pass', 'block', 'reset', 'default'], 'type': 'str'},
                        'application': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'cve': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'default-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'pass', 'all', 'drop'], 'type': 'str'},
                        'default-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'all'], 'type': 'str'},
                        'exempt-ip': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'dst-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'src-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'last-modified': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'location': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-attack-context': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-packet': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'os': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'attacker'], 'type': 'str'},
                        'quarantine-expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'quarantine-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-count': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'rate-duration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'rate-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['periodical', 'continuous'], 'type': 'str'},
                        'rate-track': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'],
                            'type': 'str'
                        },
                        'rule': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'severity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                        'vuln-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'extended-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'scan-botnet-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_sensor'),
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
