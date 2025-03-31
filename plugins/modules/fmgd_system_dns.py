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
module: fmgd_system_dns
short_description: Configure DNS.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    system_dns:
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
            cache_notfound_responses:
                aliases: ['cache-notfound-responses']
                type: str
                description: Enable/disable response from the DNS server when a record is not in cache.
                choices:
                    - 'disable'
                    - 'enable'
            dns_cache_limit:
                aliases: ['dns-cache-limit']
                type: int
                description: Maximum number of records in the DNS cache.
            dns_cache_ttl:
                aliases: ['dns-cache-ttl']
                type: int
                description: Duration in seconds that the DNS cache retains information.
            domain:
                type: list
                elements: str
                description: Search suffix list for hostname lookup.
            fqdn_cache_ttl:
                aliases: ['fqdn-cache-ttl']
                type: int
                description: FQDN cache time to live in seconds
            fqdn_max_refresh:
                aliases: ['fqdn-max-refresh']
                type: int
                description: FQDN cache maximum refresh time in seconds
            fqdn_min_refresh:
                aliases: ['fqdn-min-refresh']
                type: int
                description: FQDN cache minimum refresh time in seconds
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ip6_primary:
                aliases: ['ip6-primary']
                type: str
                description: Primary DNS server IPv6 address.
            ip6_secondary:
                aliases: ['ip6-secondary']
                type: str
                description: Secondary DNS server IPv6 address.
            log:
                type: str
                description: Local DNS log setting.
                choices:
                    - 'disable'
                    - 'error'
                    - 'all'
            primary:
                type: str
                description: Primary DNS server IP address.
            protocol:
                type: list
                elements: str
                description: DNS transport protocols.
                choices:
                    - 'cleartext'
                    - 'dot'
                    - 'doh'
            retry:
                type: int
                description: Number of times to retry
            secondary:
                type: str
                description: Secondary DNS server IP address.
            server_hostname:
                aliases: ['server-hostname']
                type: list
                elements: str
                description: DNS server host name list.
            server_select_method:
                aliases: ['server-select-method']
                type: str
                description: Specify how configured servers are prioritized.
                choices:
                    - 'least-rtt'
                    - 'failover'
            source_ip:
                aliases: ['source-ip']
                type: str
                description: IP address used by the DNS server as its source IP.
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: list
                elements: str
                description: Name of local certificate for SSL connections.
            timeout:
                type: int
                description: DNS query timeout interval in seconds
            dns_over_tls:
                aliases: ['dns-over-tls']
                type: str
                description: Enable/disable/enforce DNS over TLS.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'enforce'
            hostname_limit:
                aliases: ['hostname-limit']
                type: int
                description: Limit of the number of hostname table entries
            hostname_ttl:
                aliases: ['hostname-ttl']
                type: int
                description: TTL of hostname table entries
            root_servers:
                aliases: ['root-servers']
                type: str
                description: Configure up to two preferred servers that serve the DNS root zone
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
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure DNS.
      fortinet.fmgdevice.fmgd_system_dns:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_dns:
          # alt_primary: <string>
          # alt_secondary: <string>
          # cache_notfound_responses: <value in [disable, enable]>
          # dns_cache_limit: <integer>
          # dns_cache_ttl: <integer>
          # domain: <list or string>
          # fqdn_cache_ttl: <integer>
          # fqdn_max_refresh: <integer>
          # fqdn_min_refresh: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ip6_primary: <string>
          # ip6_secondary: <string>
          # log: <value in [disable, error, all]>
          # primary: <string>
          # protocol:
          #   - "cleartext"
          #   - "dot"
          #   - "doh"
          # retry: <integer>
          # secondary: <string>
          # server_hostname: <list or string>
          # server_select_method: <value in [least-rtt, failover]>
          # source_ip: <string>
          # ssl_certificate: <list or string>
          # timeout: <integer>
          # dns_over_tls: <value in [disable, enable, enforce]>
          # hostname_limit: <integer>
          # hostname_ttl: <integer>
          # root_servers: <string>
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
        '/pm/config/device/{device}/global/system/dns'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_dns': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'alt-primary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alt-secondary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cache-notfound-responses': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-cache-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dns-cache-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fqdn-cache-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fqdn-max-refresh': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'fqdn-min-refresh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ip6-primary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-secondary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'error', 'all'], 'type': 'str'},
                'primary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['cleartext', 'dot', 'doh'], 'elements': 'str'},
                'retry': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'secondary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'server-hostname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['least-rtt', 'failover'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dns-over-tls': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'enforce'], 'type': 'str'},
                'hostname-limit': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'hostname-ttl': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'root-servers': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dns'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
