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
module: fmgd_system_fortiguard
short_description: Configure FortiGuard services.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_fortiguard:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      antispam_cache:
        aliases: ['antispam-cache']
        type: str
        description: Enable/disable FortiGuard antispam request caching.
        choices: ['disable', 'enable']
      antispam_cache_mpercent:
        aliases: ['antispam-cache-mpercent']
        type: int
        description: Maximum percentage of FortiGate memory the antispam cache is allowed to use
      antispam_cache_ttl:
        aliases: ['antispam-cache-ttl']
        type: int
        description: Time-to-live for antispam cache entries in seconds
      antispam_expiration:
        aliases: ['antispam-expiration']
        type: int
        description: Antispam expiration.
      antispam_force_off:
        aliases: ['antispam-force-off']
        type: str
        description: Enable/disable turning off the FortiGuard antispam service.
        choices: ['disable', 'enable']
      antispam_license:
        aliases: ['antispam-license']
        type: int
        description: Antispam license.
      antispam_timeout:
        aliases: ['antispam-timeout']
        type: int
        description: Antispam query time out
      anycast_sdns_server_ip:
        aliases: ['anycast-sdns-server-ip']
        type: str
        description: IP address of the FortiGuard anycast DNS rating server.
      anycast_sdns_server_port:
        aliases: ['anycast-sdns-server-port']
        type: int
        description: Port to connect to on the FortiGuard anycast DNS rating server.
      auto_firmware_upgrade:
        aliases: ['auto-firmware-upgrade']
        type: str
        description: Enable/disable automatic patch-level firmware upgrade from FortiGuard.
        choices: ['disable', 'enable']
      auto_firmware_upgrade_day:
        aliases: ['auto-firmware-upgrade-day']
        type: list
        elements: str
        description: Allowed day
        choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
      auto_firmware_upgrade_delay:
        aliases: ['auto-firmware-upgrade-delay']
        type: int
        description: Delay of day
      auto_firmware_upgrade_end_hour:
        aliases: ['auto-firmware-upgrade-end-hour']
        type: int
        description: End time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time
      auto_firmware_upgrade_start_hour:
        aliases: ['auto-firmware-upgrade-start-hour']
        type: int
        description: Start time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time
      auto_join_forticloud:
        aliases: ['auto-join-forticloud']
        type: str
        description: Automatically connect to and login to FortiCloud.
        choices: ['disable', 'enable']
      ddns_server_ip:
        aliases: ['ddns-server-ip']
        type: str
        description: IP address of the FortiDDNS server.
      ddns_server_ip6:
        aliases: ['ddns-server-ip6']
        type: str
        description: IPv6 address of the FortiDDNS server.
      ddns_server_port:
        aliases: ['ddns-server-port']
        type: int
        description: Port used to communicate with FortiDDNS servers.
      dlp_expiration:
        aliases: ['dlp-expiration']
        type: int
        description: Dlp expiration.
      dlp_license:
        aliases: ['dlp-license']
        type: int
        description: Dlp license.
      fnbi_expiration:
        aliases: ['fnbi-expiration']
        type: int
        description: Fnbi expiration.
      fnbi_license:
        aliases: ['fnbi-license']
        type: int
        description: Fnbi license.
      fortiguard_anycast:
        aliases: ['fortiguard-anycast']
        type: str
        description: Enable/disable use of FortiGuards Anycast network.
        choices: ['disable', 'enable']
      fortiguard_anycast_source:
        aliases: ['fortiguard-anycast-source']
        type: str
        description: Configure which of Fortinets servers to provide FortiGuard services in FortiGuards anycast network.
        choices: ['fortinet', 'aws', 'debug']
      gui_prompt_auto_upgrade:
        aliases: ['gui-prompt-auto-upgrade']
        type: str
        description: Enable/disable prompting of automatic patch-level firmware upgrade recommendation.
        choices: ['disable', 'enable']
      ia_expiration:
        aliases: ['ia-expiration']
        type: int
        description: Ia expiration.
      ia_license:
        aliases: ['ia-license']
        type: int
        description: Ia license.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      load_balance_servers:
        aliases: ['load-balance-servers']
        type: int
        description: Number of servers to alternate between as first FortiGuard option.
      outbreak_prevention_cache:
        aliases: ['outbreak-prevention-cache']
        type: str
        description: Enable/disable FortiGuard Virus Outbreak Prevention cache.
        choices: ['disable', 'enable']
      outbreak_prevention_cache_mpercent:
        aliases: ['outbreak-prevention-cache-mpercent']
        type: int
        description: Maximum percent of memory FortiGuard Virus Outbreak Prevention cache can use
      outbreak_prevention_cache_ttl:
        aliases: ['outbreak-prevention-cache-ttl']
        type: int
        description: Time-to-live for FortiGuard Virus Outbreak Prevention cache entries
      outbreak_prevention_expiration:
        aliases: ['outbreak-prevention-expiration']
        type: int
        description: Outbreak prevention expiration.
      outbreak_prevention_force_off:
        aliases: ['outbreak-prevention-force-off']
        type: str
        description: Turn off FortiGuard Virus Outbreak Prevention service.
        choices: ['disable', 'enable']
      outbreak_prevention_license:
        aliases: ['outbreak-prevention-license']
        type: int
        description: Outbreak prevention license.
      outbreak_prevention_timeout:
        aliases: ['outbreak-prevention-timeout']
        type: int
        description: FortiGuard Virus Outbreak Prevention time out
      persistent_connection:
        aliases: ['persistent-connection']
        type: str
        description: Enable/disable use of persistent connection to receive update notification from FortiGuard.
        choices: ['disable', 'enable']
      port:
        type: str
        description: Port used to communicate with the FortiGuard servers.
        choices: ['53', '80', '443', '8888']
      protocol:
        type: str
        description: Protocol used to communicate with the FortiGuard servers.
        choices: ['udp', 'http', 'https']
      proxy_password:
        aliases: ['proxy-password']
        type: list
        elements: str
        description: Proxy user password.
      proxy_server_ip:
        aliases: ['proxy-server-ip']
        type: str
        description: Hostname or IPv4 address of the proxy server.
      proxy_server_port:
        aliases: ['proxy-server-port']
        type: int
        description: Port used to communicate with the proxy server.
      proxy_username:
        aliases: ['proxy-username']
        type: str
        description: Proxy user name.
      sandbox_inline_scan:
        aliases: ['sandbox-inline-scan']
        type: str
        description: Enable/disable FortiCloud Sandbox inline-scan.
        choices: ['disable', 'enable']
      sandbox_region:
        aliases: ['sandbox-region']
        type: str
        description: FortiCloud Sandbox region.
      sdns_options:
        aliases: ['sdns-options']
        type: list
        elements: str
        description: Customization options for the FortiGuard DNS service.
        choices: ['include-question-section']
      sdns_server_ip:
        aliases: ['sdns-server-ip']
        type: list
        elements: str
        description: IP address of the FortiGuard DNS rating server.
      sdns_server_port:
        aliases: ['sdns-server-port']
        type: int
        description: Port to connect to on the FortiGuard DNS rating server.
      service_account_id:
        aliases: ['service-account-id']
        type: str
        description: Service account ID.
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IPv4 address used to communicate with FortiGuard.
      source_ip6:
        aliases: ['source-ip6']
        type: str
        description: Source IPv6 address used to communicate with FortiGuard.
      update_build_proxy:
        aliases: ['update-build-proxy']
        type: str
        description: Enable/disable proxy dictionary rebuild.
        choices: ['disable', 'enable']
      update_dldb:
        aliases: ['update-dldb']
        type: str
        description: Enable/disable DLP signature update.
        choices: ['disable', 'enable']
      update_extdb:
        aliases: ['update-extdb']
        type: str
        description: Enable/disable external resource update.
        choices: ['disable', 'enable']
      update_ffdb:
        aliases: ['update-ffdb']
        type: str
        description: Enable/disable Internet Service Database update.
        choices: ['disable', 'enable']
      update_server_location:
        aliases: ['update-server-location']
        type: str
        description: Location from which to receive FortiGuard updates.
        choices: ['usa', 'automatic', 'eu', 'any']
      update_uwdb:
        aliases: ['update-uwdb']
        type: str
        description: Enable/disable allowlist update.
        choices: ['disable', 'enable']
      vdom:
        type: list
        elements: str
        description: FortiGuard Service virtual domain name.
      videofilter_expiration:
        aliases: ['videofilter-expiration']
        type: int
        description: Videofilter expiration.
      videofilter_license:
        aliases: ['videofilter-license']
        type: int
        description: Videofilter license.
      webfilter_cache:
        aliases: ['webfilter-cache']
        type: str
        description: Enable/disable FortiGuard web filter caching.
        choices: ['disable', 'enable']
      webfilter_cache_ttl:
        aliases: ['webfilter-cache-ttl']
        type: int
        description: Time-to-live for web filter cache entries in seconds
      webfilter_expiration:
        aliases: ['webfilter-expiration']
        type: int
        description: Webfilter expiration.
      webfilter_force_off:
        aliases: ['webfilter-force-off']
        type: str
        description: Enable/disable turning off the FortiGuard web filtering service.
        choices: ['disable', 'enable']
      webfilter_license:
        aliases: ['webfilter-license']
        type: int
        description: Webfilter license.
      webfilter_timeout:
        aliases: ['webfilter-timeout']
        type: int
        description: Web filter query time out
      antispam_cache_mpermille:
        aliases: ['antispam-cache-mpermille']
        type: int
        description: Maximum permille of FortiGate memory the antispam cache is allowed to use
      FDS_license_expiring_days:
        aliases: ['FDS-license-expiring-days']
        type: int
        description: Threshold for number of days before FortiGuard license expiration to generate license expiring event log
      outbreak_prevention_cache_mpermille:
        aliases: ['outbreak-prevention-cache-mpermille']
        type: int
        description: Maximum permille of memory FortiGuard Virus Outbreak Prevention cache can use
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
      subscribe_update_notification:
        aliases: ['subscribe-update-notification']
        type: str
        description: Enable/disable subscription to receive update notification from FortiGuard.
        choices: ['disable', 'enable']
      proxy_fqdn_host:
        aliases: ['proxy-fqdn-host']
        type: str
        description: Enable/disable preference of the FQDN as host header, if resolved by DNS, in the CONNECT request to FortiGuard servers.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiGuard services.
      fortinet.fmgdevice.fmgd_system_fortiguard:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_fortiguard:
          # antispam_cache: <value in [disable, enable]>
          # antispam_cache_mpercent: <integer>
          # antispam_cache_ttl: <integer>
          # antispam_expiration: <integer>
          # antispam_force_off: <value in [disable, enable]>
          # antispam_license: <integer>
          # antispam_timeout: <integer>
          # anycast_sdns_server_ip: <string>
          # anycast_sdns_server_port: <integer>
          # auto_firmware_upgrade: <value in [disable, enable]>
          # auto_firmware_upgrade_day: ["sunday", "monday", "tuesday", "wednesday", "thursday",
          #                             "friday", "saturday"]
          # auto_firmware_upgrade_delay: <integer>
          # auto_firmware_upgrade_end_hour: <integer>
          # auto_firmware_upgrade_start_hour: <integer>
          # auto_join_forticloud: <value in [disable, enable]>
          # ddns_server_ip: <string>
          # ddns_server_ip6: <string>
          # ddns_server_port: <integer>
          # dlp_expiration: <integer>
          # dlp_license: <integer>
          # fnbi_expiration: <integer>
          # fnbi_license: <integer>
          # fortiguard_anycast: <value in [disable, enable]>
          # fortiguard_anycast_source: <value in [fortinet, aws, debug]>
          # gui_prompt_auto_upgrade: <value in [disable, enable]>
          # ia_expiration: <integer>
          # ia_license: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # load_balance_servers: <integer>
          # outbreak_prevention_cache: <value in [disable, enable]>
          # outbreak_prevention_cache_mpercent: <integer>
          # outbreak_prevention_cache_ttl: <integer>
          # outbreak_prevention_expiration: <integer>
          # outbreak_prevention_force_off: <value in [disable, enable]>
          # outbreak_prevention_license: <integer>
          # outbreak_prevention_timeout: <integer>
          # persistent_connection: <value in [disable, enable]>
          # port: <value in [53, 80, 443, ...]>
          # protocol: <value in [udp, http, https]>
          # proxy_password: <list or string>
          # proxy_server_ip: <string>
          # proxy_server_port: <integer>
          # proxy_username: <string>
          # sandbox_inline_scan: <value in [disable, enable]>
          # sandbox_region: <string>
          # sdns_options: ["include-question-section"]
          # sdns_server_ip: <list or string>
          # sdns_server_port: <integer>
          # service_account_id: <string>
          # source_ip: <string>
          # source_ip6: <string>
          # update_build_proxy: <value in [disable, enable]>
          # update_dldb: <value in [disable, enable]>
          # update_extdb: <value in [disable, enable]>
          # update_ffdb: <value in [disable, enable]>
          # update_server_location: <value in [usa, automatic, eu, ...]>
          # update_uwdb: <value in [disable, enable]>
          # vdom: <list or string>
          # videofilter_expiration: <integer>
          # videofilter_license: <integer>
          # webfilter_cache: <value in [disable, enable]>
          # webfilter_cache_ttl: <integer>
          # webfilter_expiration: <integer>
          # webfilter_force_off: <value in [disable, enable]>
          # webfilter_license: <integer>
          # webfilter_timeout: <integer>
          # antispam_cache_mpermille: <integer>
          # FDS_license_expiring_days: <integer>
          # outbreak_prevention_cache_mpermille: <integer>
          # vrf_select: <integer>
          # subscribe_update_notification: <value in [disable, enable]>
          # proxy_fqdn_host: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/fortiguard'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_fortiguard': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'antispam-cache': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'antispam-cache-mpercent': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'antispam-cache-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'antispam-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'antispam-force-off': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'antispam-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'antispam-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'anycast-sdns-server-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'anycast-sdns-server-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'auto-firmware-upgrade': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-firmware-upgrade-day': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'auto-firmware-upgrade-delay': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'auto-firmware-upgrade-end-hour': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'auto-firmware-upgrade-start-hour': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'auto-join-forticloud': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-server-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ddns-server-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ddns-server-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'dlp-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'dlp-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'fnbi-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'fnbi-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'fortiguard-anycast': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-anycast-source': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['fortinet', 'aws', 'debug'], 'type': 'str'},
                'gui-prompt-auto-upgrade': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ia-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ia-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'load-balance-servers': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-cache': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention-cache-mpercent': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-cache-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-force-off': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'persistent-connection': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['53', '80', '443', '8888'], 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['udp', 'http', 'https'], 'type': 'str'},
                'proxy-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy-server-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'proxy-server-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'proxy-username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'sandbox-inline-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sandbox-region': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'sdns-options': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['include-question-section'],
                    'elements': 'str'
                },
                'sdns-server-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sdns-server-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'service-account-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'update-build-proxy': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-dldb': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-extdb': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-ffdb': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-server-location': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['usa', 'automatic', 'eu', 'any'], 'type': 'str'},
                'update-uwdb': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'videofilter-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'videofilter-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'webfilter-cache': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-cache-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'webfilter-expiration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'webfilter-force-off': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-license': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'webfilter-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'antispam-cache-mpermille': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'FDS-license-expiring-days': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'outbreak-prevention-cache-mpermille': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'subscribe-update-notification': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-fqdn-host': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fortiguard'),
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
