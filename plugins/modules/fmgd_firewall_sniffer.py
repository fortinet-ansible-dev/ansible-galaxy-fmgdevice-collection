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
module: fmgd_firewall_sniffer
short_description: Configure sniffer.
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    firewall_sniffer:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            anomaly:
                type: list
                elements: dict
                description: Anomaly.
                suboptions:
                    action:
                        type: str
                        description: Action taken when the threshold is reached.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'proxy'
                    log:
                        type: str
                        description: Enable/disable anomaly logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: Anomaly name.
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: str
                        description: Duration of quarantine.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable this anomaly.
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_mss:
                        aliases: ['synproxy-tcp-mss']
                        type: str
                        description: Determine TCP maximum segment size
                        choices:
                            - '0'
                            - '256'
                            - '512'
                            - '1024'
                            - '1300'
                            - '1360'
                            - '1460'
                            - '1500'
                    synproxy_tcp_sack:
                        aliases: ['synproxy-tcp-sack']
                        type: str
                        description: Enable/disable TCP selective acknowledage
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_timestamp:
                        aliases: ['synproxy-tcp-timestamp']
                        type: str
                        description: Enable/disable TCP timestamp option for packets replied by syn proxy module.
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_window:
                        aliases: ['synproxy-tcp-window']
                        type: str
                        description: Determine TCP Window size for packets replied by syn proxy module.
                        choices:
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                    synproxy_tcp_windowscale:
                        aliases: ['synproxy-tcp-windowscale']
                        type: str
                        description: Determine TCP window scale option value for packets replied by syn proxy module.
                        choices:
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                    synproxy_tos:
                        aliases: ['synproxy-tos']
                        type: str
                        description: Determine TCP differentiated services code point value
                        choices:
                            - '0'
                            - '10'
                            - '12'
                            - '14'
                            - '18'
                            - '20'
                            - '22'
                            - '26'
                            - '28'
                            - '30'
                            - '34'
                            - '36'
                            - '38'
                            - '40'
                            - '46'
                            - '255'
                    synproxy_ttl:
                        aliases: ['synproxy-ttl']
                        type: str
                        description: Determine Time to live
                        choices:
                            - '32'
                            - '64'
                            - '128'
                            - '255'
                    threshold:
                        type: int
                        description: Anomaly threshold.
                    threshold_default:
                        aliases: ['threshold(default)']
                        type: int
                        description: Threshold
            application_list:
                aliases: ['application-list']
                type: list
                elements: str
                description: Name of an existing application list.
            application_list_status:
                aliases: ['application-list-status']
                type: str
                description: Enable/disable application control profile.
                choices:
                    - 'disable'
                    - 'enable'
            av_profile:
                aliases: ['av-profile']
                type: list
                elements: str
                description: Name of an existing antivirus profile.
            av_profile_status:
                aliases: ['av-profile-status']
                type: str
                description: Enable/disable antivirus profile.
                choices:
                    - 'disable'
                    - 'enable'
            dlp_profile:
                aliases: ['dlp-profile']
                type: list
                elements: str
                description: Name of an existing DLP profile.
            dlp_profile_status:
                aliases: ['dlp-profile-status']
                type: str
                description: Enable/disable DLP profile.
                choices:
                    - 'disable'
                    - 'enable'
            dsri:
                type: str
                description: Enable/disable DSRI.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: list
                elements: str
                description: Name of an existing email filter profile.
            emailfilter_profile_status:
                aliases: ['emailfilter-profile-status']
                type: str
                description: Enable/disable emailfilter.
                choices:
                    - 'disable'
                    - 'enable'
            file_filter_profile:
                aliases: ['file-filter-profile']
                type: list
                elements: str
                description: Name of an existing file-filter profile.
            file_filter_profile_status:
                aliases: ['file-filter-profile-status']
                type: str
                description: Enable/disable file filter.
                choices:
                    - 'disable'
                    - 'enable'
            host:
                type: str
                description: Hosts to filter for in sniffer traffic
            id:
                type: int
                description: Sniffer ID
                required: true
            interface:
                type: list
                elements: str
                description: Interface name that traffic sniffing will take place on.
            ip_threatfeed:
                aliases: ['ip-threatfeed']
                type: list
                elements: str
                description: Name of an existing IP threat feed.
            ip_threatfeed_status:
                aliases: ['ip-threatfeed-status']
                type: str
                description: Enable/disable IP threat feed.
                choices:
                    - 'disable'
                    - 'enable'
            ips_dos_status:
                aliases: ['ips-dos-status']
                type: str
                description: Enable/disable IPS DoS anomaly detection.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: list
                elements: str
                description: Name of an existing IPS sensor.
            ips_sensor_status:
                aliases: ['ips-sensor-status']
                type: str
                description: Enable/disable IPS sensor.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6:
                type: str
                description: Enable/disable sniffing IPv6 packets.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Either log all sessions, only sessions that have a security profile applied, or disable all logging for this policy.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            non_ip:
                aliases: ['non-ip']
                type: str
                description: Enable/disable sniffing non-IP packets.
                choices:
                    - 'disable'
                    - 'enable'
            port:
                type: str
                description: Ports to sniff
            protocol:
                type: str
                description: Integer value for the protocol type as defined by IANA
            status:
                type: str
                description: Enable/disable the active status of the sniffer.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            vlan:
                type: str
                description: List of VLANs to sniff.
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: list
                elements: str
                description: Name of an existing web filter profile.
            webfilter_profile_status:
                aliases: ['webfilter-profile-status']
                type: str
                description: Enable/disable web filter profile.
                choices:
                    - 'disable'
                    - 'enable'
            max_packet_count:
                aliases: ['max-packet-count']
                type: int
                description: Maximum packet count
            dlp_sensor_status:
                aliases: ['dlp-sensor-status']
                type: str
                description: Enable/disable DLP sensor.
                choices:
                    - 'disable'
                    - 'enable'
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: list
                elements: str
                description: Name of an existing DLP sensor.
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
    - name: Configure sniffer.
      fortinet.fmgdevice.fmgd_firewall_sniffer:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_sniffer:
          id: 0 # Required variable, integer
          # anomaly:
          #   - action: <value in [pass, block, proxy]>
          #     log: <value in [disable, enable]>
          #     name: <string>
          #     quarantine: <value in [none, attacker, both, ...]>
          #     quarantine_expiry: <string>
          #     quarantine_log: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          #     synproxy_tcp_mss: <value in [0, 256, 512, ...]>
          #     synproxy_tcp_sack: <value in [disable, enable]>
          #     synproxy_tcp_timestamp: <value in [disable, enable]>
          #     synproxy_tcp_window: <value in [4096, 8192, 16384, ...]>
          #     synproxy_tcp_windowscale: <value in [0, 1, 2, ...]>
          #     synproxy_tos: <value in [0, 10, 12, ...]>
          #     synproxy_ttl: <value in [32, 64, 128, ...]>
          #     threshold: <integer>
          #     threshold_default: <integer>
          # application_list: <list or string>
          # application_list_status: <value in [disable, enable]>
          # av_profile: <list or string>
          # av_profile_status: <value in [disable, enable]>
          # dlp_profile: <list or string>
          # dlp_profile_status: <value in [disable, enable]>
          # dsri: <value in [disable, enable]>
          # emailfilter_profile: <list or string>
          # emailfilter_profile_status: <value in [disable, enable]>
          # file_filter_profile: <list or string>
          # file_filter_profile_status: <value in [disable, enable]>
          # host: <string>
          # interface: <list or string>
          # ip_threatfeed: <list or string>
          # ip_threatfeed_status: <value in [disable, enable]>
          # ips_dos_status: <value in [disable, enable]>
          # ips_sensor: <list or string>
          # ips_sensor_status: <value in [disable, enable]>
          # ipv6: <value in [disable, enable]>
          # logtraffic: <value in [disable, all, utm]>
          # non_ip: <value in [disable, enable]>
          # port: <string>
          # protocol: <string>
          # status: <value in [disable, enable]>
          # uuid: <string>
          # vlan: <string>
          # webfilter_profile: <list or string>
          # webfilter_profile_status: <value in [disable, enable]>
          # max_packet_count: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_sniffer': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'anomaly': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['pass', 'block', 'proxy'], 'type': 'str'},
                        'log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'quarantine': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['none', 'attacker', 'both', 'interface'],
                            'type': 'str'
                        },
                        'quarantine-expiry': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'quarantine-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-mss': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                            'type': 'str'
                        },
                        'synproxy-tcp-sack': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-timestamp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-window': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['4096', '8192', '16384', '32768'],
                            'type': 'str'
                        },
                        'synproxy-tcp-windowscale': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                            'type': 'str'
                        },
                        'synproxy-tos': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                            'type': 'str'
                        },
                        'synproxy-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['32', '64', '128', '255'], 'type': 'str'},
                        'threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold(default)': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'application-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'application-list-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'av-profile-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dlp-profile-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dsri': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'emailfilter-profile-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-filter-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'file-filter-profile-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'host': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-threatfeed': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-threatfeed-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-dos-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ips-sensor-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'non-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'webfilter-profile-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-packet-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dlp-sensor-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-sensor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sniffer'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
