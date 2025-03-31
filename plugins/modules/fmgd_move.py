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
module: fmgd_move
short_description: Move fortimanager defined Object.
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
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of forticloud managed API users, this option is available with FortiManager later than 6.4.0.
        required: false
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    move:
        description: Reorder Two Objects.
        type: dict
        required: true
        suboptions:
            action:
                required: true
                description: Direction to indicate where to move an object entry.
                type: str
                choices:
                    - after
                    - before
            selector:
                required: true
                description: Selector of the move object.
                type: str
                choices:
                    - 'casb_attributematch'
                    - 'dlp_exactdatamatch_columns'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_policy'
                    - 'firewall_sniffer'
                    - 'firewall_ttlpolicy'
                    - 'gtp_apnshaper'
                    - 'nsxt_servicechain_serviceindex'
                    - 'report_layout_bodyitem'
                    - 'report_layout_page_footer_footeritem'
                    - 'report_layout_page_header_headeritem'
                    - 'router_policy'
                    - 'router_policy6'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_managedswitch'
                    - 'system_automationstitch_actions'
                    - 'system_healthcheckfortiguard'
                    - 'system_ipam_rules'
                    - 'system_sdwan_members'
                    - 'system_sdwan_service'
                    - 'system_sdwan_service_sla'
                    - 'system_sdwan_zone'
                    - 'system_virtualwanlink_members'
                    - 'system_virtualwanlink_service'
                    - 'system_virtualwanlink_service_sla'
                    - 'user_nacpolicy'
                    - 'vpn_kmipserver_serverlist'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnsslweb_userbookmark_bookmarks'
                    - 'vpnsslweb_usergroupbookmark_bookmarks'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_apcfgprofile_commandlist'
                    - 'wireless_bonjourprofile_policylist'
                    - 'wireless_mpskprofile_mpskgroup'
                    - 'wireless_mpskprofile_mpskgroup_mpskkey'
                    - 'wireless_vap_vlanname'
                    - 'wireless_wtp'
                    - 'ztna_webportalbookmark_bookmarks'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Key to the target entry.
                type: str
'''

EXAMPLES = '''
  - name: Move an object.
    hosts: fortimanagers
    connection: httpapi
    vars:
      device_name: "FGVMMLTMXXXXX"
      vdom_name: "root"
    tasks:
      - name: Move an object.
        fortinet.fmgdevice.fmgd_move:
          move:
            selector: "router_policy"
            self:
              device: "{{ device_name }}"
              vdom: "{{ vdom_name }}"
              policy: "1" # seq-num
            target: "2" # seq-num
            action: "after"
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
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager


def main():
    move_metadata = {
        'casb_attributematch': {
            'params': ['attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['columns', 'device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'v_range': [['7.2.6', '7.2.9']]
        },
        'firewall_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy/{policy}'
            ]
        },
        'firewall_sniffer': {
            'params': ['device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ttlpolicy': {
            'params': ['device', 'ttl-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy/{ttl-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'gtp_apnshaper': {
            'params': ['apn-shaper', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper/{apn-shaper}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_servicechain_serviceindex': {
            'params': ['device', 'service-chain', 'service-index'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index/{service-index}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem': {
            'params': ['body-item', 'device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_footer_footeritem': {
            'params': ['device', 'footer-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item/{footer-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_header_headeritem': {
            'params': ['device', 'header-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item/{header-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy6': {
            'params': ['device', 'policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6/{policy6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['device', 'dynamic-port-policy', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationstitch_actions': {
            'params': ['actions', 'automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions/{actions}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_healthcheckfortiguard': {
            'params': ['device', 'health-check-fortiguard'],
            'urls': [
                '/pm/config/device/{device}/global/system/health-check-fortiguard/{health-check-fortiguard}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_ipam_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/rules/{rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone/{zone}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_nacpolicy': {
            'params': ['device', 'nac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy/{nac-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_kmipserver_serverlist': {
            'params': ['device', 'kmip-server', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}/server-list/{server-list}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnsslweb_userbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv4-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv6-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile_commandlist': {
            'params': ['apcfg-profile', 'command-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile_policylist': {
            'params': ['bonjour-profile', 'device', 'policy-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup': {
            'params': ['device', 'mpsk-group', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup_mpskkey': {
            'params': ['device', 'mpsk-group', 'mpsk-key', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_vlanname': {
            'params': ['device', 'vap', 'vdom', 'vlan-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ztna_webportalbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'vdom', 'web-portal-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.6.2', '']]
        }
    }

    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'workspace_locking_adom': {'type': 'str'},
        'workspace_locking_timeout': {'type': 'int', 'default': 300},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'move': {
            'required': True,
            'type': 'dict',
            'options': {
                'action': {'required': True, 'type': 'str', 'choices': ['after', 'before']},
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(move_metadata.keys())
                },
                'self': {'required': True, 'type': 'dict'},
                'target': {'required': True, 'type': 'str'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('move', move_metadata, None, None, None, module, connection)
    fmgd.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
