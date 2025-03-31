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
module: fmgd_wireless_hotspot20_hsprofile
short_description: Configure hotspot profile.
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
    wireless_hotspot20_hsprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            3gpp_plmn:
                aliases: ['3gpp-plmn']
                type: list
                elements: str
                description: 3GPP PLMN name.
            access_network_asra:
                aliases: ['access-network-asra']
                type: str
                description: Enable/disable additional step required for access
                choices:
                    - 'disable'
                    - 'enable'
            access_network_esr:
                aliases: ['access-network-esr']
                type: str
                description: Enable/disable emergency services reachable
                choices:
                    - 'disable'
                    - 'enable'
            access_network_internet:
                aliases: ['access-network-internet']
                type: str
                description: Enable/disable connectivity to the Internet.
                choices:
                    - 'disable'
                    - 'enable'
            access_network_type:
                aliases: ['access-network-type']
                type: str
                description: Access network type.
                choices:
                    - 'private-network'
                    - 'private-network-with-guest-access'
                    - 'chargeable-public-network'
                    - 'free-public-network'
                    - 'personal-device-network'
                    - 'emergency-services-only-network'
                    - 'test-or-experimental'
                    - 'wildcard'
            access_network_uesa:
                aliases: ['access-network-uesa']
                type: str
                description: Enable/disable unauthenticated emergency service accessible
                choices:
                    - 'disable'
                    - 'enable'
            advice_of_charge:
                aliases: ['advice-of-charge']
                type: list
                elements: str
                description: Advice of charge.
            anqp_domain_id:
                aliases: ['anqp-domain-id']
                type: int
                description: ANQP Domain ID
            bss_transition:
                aliases: ['bss-transition']
                type: str
                description: Enable/disable basic service set
                choices:
                    - 'disable'
                    - 'enable'
            conn_cap:
                aliases: ['conn-cap']
                type: list
                elements: str
                description: Connection capability name.
            deauth_request_timeout:
                aliases: ['deauth-request-timeout']
                type: int
                description: Deauthentication request timeout
            dgaf:
                type: str
                description: Enable/disable downstream group-addressed forwarding
                choices:
                    - 'disable'
                    - 'enable'
            domain_name:
                aliases: ['domain-name']
                type: str
                description: Domain name.
            gas_comeback_delay:
                aliases: ['gas-comeback-delay']
                type: int
                description: GAS comeback delay
            gas_fragmentation_limit:
                aliases: ['gas-fragmentation-limit']
                type: int
                description: GAS fragmentation limit
            hessid:
                type: str
                description: Homogeneous extended service set identifier
            ip_addr_type:
                aliases: ['ip-addr-type']
                type: list
                elements: str
                description: IP address type name.
            l2tif:
                type: str
                description: Enable/disable Layer 2 traffic inspection and filtering.
                choices:
                    - 'disable'
                    - 'enable'
            nai_realm:
                aliases: ['nai-realm']
                type: list
                elements: str
                description: NAI realm list name.
            name:
                type: str
                description: Hotspot profile name.
                required: true
            network_auth:
                aliases: ['network-auth']
                type: list
                elements: str
                description: Network authentication name.
            oper_friendly_name:
                aliases: ['oper-friendly-name']
                type: list
                elements: str
                description: Operator friendly name.
            oper_icon:
                aliases: ['oper-icon']
                type: list
                elements: str
                description: Operator icon.
            osu_provider:
                aliases: ['osu-provider']
                type: list
                elements: str
                description: Manually selected list of OSU provider
            osu_provider_nai:
                aliases: ['osu-provider-nai']
                type: list
                elements: str
                description: OSU Provider NAI.
            osu_ssid:
                aliases: ['osu-ssid']
                type: str
                description: Online sign up
            pame_bi:
                aliases: ['pame-bi']
                type: str
                description: Enable/disable Pre-Association Message Exchange BSSID Independent
                choices:
                    - 'disable'
                    - 'enable'
            proxy_arp:
                aliases: ['proxy-arp']
                type: str
                description: Enable/disable Proxy ARP.
                choices:
                    - 'disable'
                    - 'enable'
            qos_map:
                aliases: ['qos-map']
                type: list
                elements: str
                description: QoS MAP set ID.
            release:
                type: int
                description: Hotspot 2.
            roaming_consortium:
                aliases: ['roaming-consortium']
                type: list
                elements: str
                description: Roaming consortium list name.
            terms_and_conditions:
                aliases: ['terms-and-conditions']
                type: list
                elements: str
                description: Terms and conditions.
            venue_group:
                aliases: ['venue-group']
                type: str
                description: Venue group.
                choices:
                    - 'unspecified'
                    - 'assembly'
                    - 'business'
                    - 'educational'
                    - 'factory'
                    - 'institutional'
                    - 'mercantile'
                    - 'residential'
                    - 'storage'
                    - 'utility'
                    - 'vehicular'
                    - 'outdoor'
            venue_name:
                aliases: ['venue-name']
                type: list
                elements: str
                description: Venue name.
            venue_type:
                aliases: ['venue-type']
                type: str
                description: Venue type.
                choices:
                    - 'unspecified'
                    - 'arena'
                    - 'stadium'
                    - 'passenger-terminal'
                    - 'amphitheater'
                    - 'amusement-park'
                    - 'place-of-worship'
                    - 'convention-center'
                    - 'library'
                    - 'museum'
                    - 'restaurant'
                    - 'theater'
                    - 'bar'
                    - 'coffee-shop'
                    - 'zoo-or-aquarium'
                    - 'emergency-center'
                    - 'doctor-office'
                    - 'bank'
                    - 'fire-station'
                    - 'police-station'
                    - 'post-office'
                    - 'professional-office'
                    - 'research-facility'
                    - 'attorney-office'
                    - 'primary-school'
                    - 'secondary-school'
                    - 'university-or-college'
                    - 'factory'
                    - 'hospital'
                    - 'long-term-care-facility'
                    - 'rehab-center'
                    - 'group-home'
                    - 'prison-or-jail'
                    - 'retail-store'
                    - 'grocery-market'
                    - 'auto-service-station'
                    - 'shopping-mall'
                    - 'gas-station'
                    - 'private'
                    - 'hotel-or-motel'
                    - 'dormitory'
                    - 'boarding-house'
                    - 'automobile'
                    - 'airplane'
                    - 'bus'
                    - 'ferry'
                    - 'ship-or-boat'
                    - 'train'
                    - 'motor-bike'
                    - 'muni-mesh-network'
                    - 'city-park'
                    - 'rest-area'
                    - 'traffic-control'
                    - 'bus-stop'
                    - 'kiosk'
            venue_url:
                aliases: ['venue-url']
                type: list
                elements: str
                description: Venue name.
            wan_metrics:
                aliases: ['wan-metrics']
                type: list
                elements: str
                description: WAN metric name.
            wnm_sleep_mode:
                aliases: ['wnm-sleep-mode']
                type: str
                description: Enable/disable wireless network management
                choices:
                    - 'disable'
                    - 'enable'
            wba_charging_currency:
                aliases: ['wba-charging-currency']
                type: str
                description: Three letter currency code.
            wba_charging_rate:
                aliases: ['wba-charging-rate']
                type: int
                description: Number of currency units per kilobyte.
            wba_data_clearing_provider:
                aliases: ['wba-data-clearing-provider']
                type: str
                description: WBA ID of data clearing provider.
            wba_financial_clearing_provider:
                aliases: ['wba-financial-clearing-provider']
                type: str
                description: WBA ID of financial clearing provider.
            wba_open_roaming:
                aliases: ['wba-open-roaming']
                type: str
                description: Enable/disable WBA open roaming support.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure hotspot profile.
      fortinet.fmgdevice.fmgd_wireless_hotspot20_hsprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_hotspot20_hsprofile:
          name: "your value" # Required variable, string
          # 3gpp_plmn: <list or string>
          # access_network_asra: <value in [disable, enable]>
          # access_network_esr: <value in [disable, enable]>
          # access_network_internet: <value in [disable, enable]>
          # access_network_type: <value in [private-network, private-network-with-guest-access, chargeable-public-network, ...]>
          # access_network_uesa: <value in [disable, enable]>
          # advice_of_charge: <list or string>
          # anqp_domain_id: <integer>
          # bss_transition: <value in [disable, enable]>
          # conn_cap: <list or string>
          # deauth_request_timeout: <integer>
          # dgaf: <value in [disable, enable]>
          # domain_name: <string>
          # gas_comeback_delay: <integer>
          # gas_fragmentation_limit: <integer>
          # hessid: <string>
          # ip_addr_type: <list or string>
          # l2tif: <value in [disable, enable]>
          # nai_realm: <list or string>
          # network_auth: <list or string>
          # oper_friendly_name: <list or string>
          # oper_icon: <list or string>
          # osu_provider: <list or string>
          # osu_provider_nai: <list or string>
          # osu_ssid: <string>
          # pame_bi: <value in [disable, enable]>
          # proxy_arp: <value in [disable, enable]>
          # qos_map: <list or string>
          # release: <integer>
          # roaming_consortium: <list or string>
          # terms_and_conditions: <list or string>
          # venue_group: <value in [unspecified, assembly, business, ...]>
          # venue_name: <list or string>
          # venue_type: <value in [unspecified, arena, stadium, ...]>
          # venue_url: <list or string>
          # wan_metrics: <list or string>
          # wnm_sleep_mode: <value in [disable, enable]>
          # wba_charging_currency: <string>
          # wba_charging_rate: <integer>
          # wba_data_clearing_provider: <string>
          # wba_financial_clearing_provider: <string>
          # wba_open_roaming: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/hs-profile'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_hotspot20_hsprofile': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                '3gpp-plmn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'access-network-asra': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'access-network-esr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'access-network-internet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'access-network-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'private-network', 'private-network-with-guest-access', 'chargeable-public-network', 'free-public-network',
                        'personal-device-network', 'emergency-services-only-network', 'test-or-experimental', 'wildcard'
                    ],
                    'type': 'str'
                },
                'access-network-uesa': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'advice-of-charge': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'anqp-domain-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bss-transition': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'conn-cap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'deauth-request-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dgaf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'domain-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gas-comeback-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'gas-fragmentation-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hessid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip-addr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'l2tif': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nai-realm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'network-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'oper-friendly-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'oper-icon': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'osu-provider': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'osu-provider-nai': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'osu-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pame-bi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-arp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'qos-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'release': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'roaming-consortium': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'terms-and-conditions': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'venue-group': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'unspecified', 'assembly', 'business', 'educational', 'factory', 'institutional', 'mercantile', 'residential', 'storage',
                        'utility', 'vehicular', 'outdoor'
                    ],
                    'type': 'str'
                },
                'venue-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'venue-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'unspecified', 'arena', 'stadium', 'passenger-terminal', 'amphitheater', 'amusement-park', 'place-of-worship',
                        'convention-center', 'library', 'museum', 'restaurant', 'theater', 'bar', 'coffee-shop', 'zoo-or-aquarium', 'emergency-center',
                        'doctor-office', 'bank', 'fire-station', 'police-station', 'post-office', 'professional-office', 'research-facility',
                        'attorney-office', 'primary-school', 'secondary-school', 'university-or-college', 'factory', 'hospital',
                        'long-term-care-facility', 'rehab-center', 'group-home', 'prison-or-jail', 'retail-store', 'grocery-market',
                        'auto-service-station', 'shopping-mall', 'gas-station', 'private', 'hotel-or-motel', 'dormitory', 'boarding-house', 'automobile',
                        'airplane', 'bus', 'ferry', 'ship-or-boat', 'train', 'motor-bike', 'muni-mesh-network', 'city-park', 'rest-area',
                        'traffic-control', 'bus-stop', 'kiosk'
                    ],
                    'type': 'str'
                },
                'venue-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'wan-metrics': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'wnm-sleep-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wba-charging-currency': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'wba-charging-rate': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'wba-data-clearing-provider': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'wba-financial-clearing-provider': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'wba-open-roaming': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_hotspot20_hsprofile'),
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
