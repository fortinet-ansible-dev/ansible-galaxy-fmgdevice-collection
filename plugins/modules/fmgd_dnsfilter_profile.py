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
module: fmgd_dnsfilter_profile
short_description: Configure DNS domain filter profile.
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
  dnsfilter_profile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      block_action:
        aliases: ['block-action']
        type: str
        description: Action to take for blocked domains.
        choices: ['block', 'redirect', 'block-sevrfail']
      block_botnet:
        aliases: ['block-botnet']
        type: str
        description: Enable/disable blocking botnet C&C DNS lookups.
        choices: ['disable', 'enable']
      comment:
        type: str
        description: Comment.
      dns_translation:
        aliases: ['dns-translation']
        type: list
        elements: dict
        description: Dns translation.
        suboptions:
          addr_type:
            aliases: ['addr-type']
            type: str
            description: DNS translation type
            choices: ['ipv4', 'ipv6']
          dst:
            type: str
            description: IPv4 address or subnet on the external network to substitute for the resolved address in DNS query replies.
          dst6:
            type: str
            description: IPv6 address or subnet on the external network to substitute for the resolved address in DNS query replies.
          id:
            type: int
            description: ID.
          netmask:
            type: str
            description: If src and dst are subnets rather than single IP addresses, enter the netmask for both src and dst.
          prefix:
            type: int
            description: If src6 and dst6 are subnets rather than single IP addresses, enter the prefix for both src6 and dst6
          src:
            type: str
            description: IPv4 address or subnet on the internal network to compare with the resolved address in DNS query replies.
          src6:
            type: str
            description: IPv6 address or subnet on the internal network to compare with the resolved address in DNS query replies.
          status:
            type: str
            description: Enable/disable this DNS translation entry.
            choices: ['disable', 'enable']
      domain_filter:
        aliases: ['domain-filter']
        type: dict
        description: Domain filter.
        suboptions:
          domain_filter_table:
            aliases: ['domain-filter-table']
            type: list
            elements: str
            description: DNS domain filter table ID.
      external_ip_blocklist:
        aliases: ['external-ip-blocklist']
        type: list
        elements: str
        description: One or more external IP block lists.
      ftgd_dns:
        aliases: ['ftgd-dns']
        type: dict
        description: Ftgd dns.
        suboptions:
          filters:
            type: list
            elements: dict
            description: Filters.
            suboptions:
              action:
                type: str
                description: Action to take for DNS requests matching the category.
                choices: ['monitor', 'block']
              category:
                type: list
                elements: str
                description: Category number.
              id:
                type: int
                description: ID number.
              log:
                type: str
                description: Enable/disable DNS filter logging for this DNS profile.
                choices: ['disable', 'enable']
          options:
            type: list
            elements: str
            description: FortiGuard DNS filter options.
            choices: ['error-allow', 'ftgd-disable']
      log_all_domain:
        aliases: ['log-all-domain']
        type: str
        description: Enable/disable logging of all domains visited
        choices: ['disable', 'enable']
      name:
        type: str
        description: Profile name.
        required: true
      redirect_portal:
        aliases: ['redirect-portal']
        type: str
        description: IPv4 address of the SDNS redirect portal.
      redirect_portal6:
        aliases: ['redirect-portal6']
        type: str
        description: IPv6 address of the SDNS redirect portal.
      safe_search:
        aliases: ['safe-search']
        type: str
        description: Enable/disable Google, Bing, YouTube, Qwant, DuckDuckGo safe search.
        choices: ['disable', 'enable']
      sdns_domain_log:
        aliases: ['sdns-domain-log']
        type: str
        description: Enable/disable domain filtering and botnet domain logging.
        choices: ['disable', 'enable']
      sdns_ftgd_err_log:
        aliases: ['sdns-ftgd-err-log']
        type: str
        description: Enable/disable FortiGuard SDNS rating error logging.
        choices: ['disable', 'enable']
      strip_ech:
        aliases: ['strip-ech']
        type: str
        description: Enable/disable removal of the encrypted client hello service parameter from supporting DNS RRs.
        choices: ['disable', 'enable']
      youtube_restrict:
        aliases: ['youtube-restrict']
        type: str
        description: Set safe search for YouTube restriction level.
        choices: ['strict', 'moderate', 'none']
      transparent_dns_database:
        aliases: ['transparent-dns-database']
        type: list
        elements: str
        description:
          - Support meta variable
          - Transparent DNS database zones.
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
    - name: Configure DNS domain filter profile.
      fortinet.fmgdevice.fmgd_dnsfilter_profile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        dnsfilter_profile:
          name: "your value" # Required variable, string
          # block_action: <value in [block, redirect, block-sevrfail]>
          # block_botnet: <value in [disable, enable]>
          # comment: <string>
          # dns_translation:
          #   - addr_type: <value in [ipv4, ipv6]>
          #     dst: <string>
          #     dst6: <string>
          #     id: <integer>
          #     netmask: <string>
          #     prefix: <integer>
          #     src: <string>
          #     src6: <string>
          #     status: <value in [disable, enable]>
          # domain_filter:
          #   domain_filter_table: <list or string>
          # external_ip_blocklist: <list or string>
          # ftgd_dns:
          #   filters:
          #     - action: <value in [monitor, block]>
          #       category: <list or string>
          #       id: <integer>
          #       log: <value in [disable, enable]>
          #   options: ["error-allow", "ftgd-disable"]
          # log_all_domain: <value in [disable, enable]>
          # redirect_portal: <string>
          # redirect_portal6: <string>
          # safe_search: <value in [disable, enable]>
          # sdns_domain_log: <value in [disable, enable]>
          # sdns_ftgd_err_log: <value in [disable, enable]>
          # strip_ech: <value in [disable, enable]>
          # youtube_restrict: <value in [strict, moderate, none]>
          # transparent_dns_database: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'dnsfilter_profile': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'block-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'redirect', 'block-sevrfail'], 'type': 'str'},
                'block-botnet': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dns-translation': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'addr-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'dst': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'dst6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'netmask': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'prefix': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'src': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'src6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'domain-filter': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {'domain-filter-table': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}}
                },
                'external-ip-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ftgd-dns': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'filters': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['monitor', 'block'], 'type': 'str'},
                                'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['error-allow', 'ftgd-disable'],
                            'elements': 'str'
                        }
                    }
                },
                'log-all-domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'redirect-portal': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'redirect-portal6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'safe-search': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sdns-domain-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sdns-ftgd-err-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strip-ech': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'youtube-restrict': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['strict', 'moderate', 'none'], 'type': 'str'},
                'transparent-dns-database': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dnsfilter_profile'),
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
