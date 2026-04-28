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
                    - 'application_list_defaultnetworkservices'
                    - 'application_list_entries'
                    - 'authentication_rule'
                    - 'casb_attributematch'
                    - 'casb_profile'
                    - 'casb_saasapplication'
                    - 'casb_useractivity'
                    - 'dlp_dictionary_entries'
                    - 'dlp_exactdatamatch_columns'
                    - 'dlp_filepattern_entries'
                    - 'dlp_label_entries'
                    - 'dlp_profile_rule'
                    - 'dlp_sensor_entries'
                    - 'dnsfilter_domainfilter_entries'
                    - 'emailfilter_blockallowlist_entries'
                    - 'emailfilter_bword_entries'
                    - 'endpointcontrol_fctems'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxyvirtualhost'
                    - 'firewall_centralsnatmap'
                    - 'firewall_dospolicy'
                    - 'firewall_dospolicy6'
                    - 'firewall_identitybasedroute'
                    - 'firewall_interfacepolicy'
                    - 'firewall_interfacepolicy6'
                    - 'firewall_localinpolicy'
                    - 'firewall_localinpolicy6'
                    - 'firewall_multicastpolicy'
                    - 'firewall_multicastpolicy6'
                    - 'firewall_policy'
                    - 'firewall_proxypolicy'
                    - 'firewall_responseshapingpolicy'
                    - 'firewall_securitypolicy'
                    - 'firewall_service_category'
                    - 'firewall_service_custom'
                    - 'firewall_shapingpolicy'
                    - 'firewall_shapingprofile_shapingentries'
                    - 'firewall_sniffer'
                    - 'firewall_ttlpolicy'
                    - 'firewall_vip'
                    - 'firewall_vip6'
                    - 'gtp_apnshaper'
                    - 'icap_localserver_icapservice'
                    - 'ips_sensor_entries'
                    - 'isolator_profile_entries'
                    - 'llm_server'
                    - 'nsxt_servicechain_serviceindex'
                    - 'report_layout_bodyitem'
                    - 'report_layout_page_footer_footeritem'
                    - 'report_layout_page_header_headeritem'
                    - 'router_policy'
                    - 'router_policy6'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_managedswitch'
                    - 'system_automationstitch_actions'
                    - 'system_externalresource'
                    - 'system_healthcheckfortiguard'
                    - 'system_ipam_rules'
                    - 'system_sdnconnector_compartmentlist'
                    - 'system_sdnconnector_externalaccountlist'
                    - 'system_sdnconnector_forwardingrule'
                    - 'system_sdnconnector_ociregionlist'
                    - 'system_sdnconnector_routetable'
                    - 'system_sdwan_members'
                    - 'system_sdwan_service'
                    - 'system_sdwan_service_sla'
                    - 'system_sdwan_zone'
                    - 'system_virtualwanlink_members'
                    - 'system_virtualwanlink_service'
                    - 'system_virtualwanlink_service_sla'
                    - 'user_nacpolicy'
                    - 'videofilter_profile_filters'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'vpn_ipsec_fec_mappings'
                    - 'vpn_kmipserver_serverlist'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnsslweb_portal_bookmarkgroup'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks'
                    - 'vpnsslweb_portal_splitdns'
                    - 'vpnsslweb_userbookmark_bookmarks'
                    - 'vpnsslweb_usergroupbookmark_bookmarks'
                    - 'webfilter_contentheader_entries'
                    - 'webfilter_urlfilter_entries'
                    - 'webproxy_redirectprofile_entries'
                    - 'webproxy_urllist_entries'
                    - 'webproxy_urlmatch'
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
        'application_list_defaultnetworkservices': {
            'params': ['default-network-services', 'device', 'list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_list_entries': {
            'params': ['device', 'entries', 'list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'authentication_rule': {
            'params': ['device', 'rule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/authentication/rule/{rule}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_attributematch': {
            'params': ['attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_profile': {
            'params': ['device', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_saasapplication': {
            'params': ['device', 'saas-application', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/saas-application/{saas-application}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_useractivity': {
            'params': ['device', 'user-activity', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_dictionary_entries': {
            'params': ['device', 'dictionary', 'entries', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['columns', 'device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'v_range': [['7.4.3', '7.4.6'], ['7.4.8', '7.6.2'], ['7.6.4', '']]
        },
        'dlp_filepattern_entries': {
            'params': ['device', 'entries', 'filepattern', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/filepattern/{filepattern}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_label_entries': {
            'params': ['device', 'entries', 'label', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/label/{label}/entries/{entries}'
            ],
            'v_range': [['7.6.4', '']]
        },
        'dlp_profile_rule': {
            'params': ['device', 'profile', 'rule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/profile/{profile}/rule/{rule}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_sensor_entries': {
            'params': ['device', 'entries', 'sensor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_domainfilter_entries': {
            'params': ['device', 'domain-filter', 'entries', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_blockallowlist_entries': {
            'params': ['block-allow-list', 'device', 'entries', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_bword_entries': {
            'params': ['bword', 'device', 'entries', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'endpointcontrol_fctems': {
            'params': ['device', 'fctems'],
            'urls': [
                '/pm/config/device/{device}/global/endpoint-control/fctems/{fctems}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['device', 'extender-profile', 'receiver', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver'
                '}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'filefilter_profile_rules': {
            'params': ['device', 'profile', 'rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/file-filter/profile/{profile}/rules/{rules}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy': {
            'params': ['access-proxy', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6': {
            'params': ['access-proxy6', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxyvirtualhost': {
            'params': ['access-proxy-virtual-host', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_centralsnatmap': {
            'params': ['central-snat-map', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/central-snat-map/{central-snat-map}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_dospolicy': {
            'params': ['DoS-policy', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy/{DoS-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_dospolicy6': {
            'params': ['DoS-policy6', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy6/{DoS-policy6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_identitybasedroute': {
            'params': ['device', 'identity-based-route', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/identity-based-route/{identity-based-route}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_interfacepolicy': {
            'params': ['device', 'interface-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/interface-policy/{interface-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_interfacepolicy6': {
            'params': ['device', 'interface-policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/interface-policy6/{interface-policy6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_localinpolicy': {
            'params': ['device', 'local-in-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy/{local-in-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_localinpolicy6': {
            'params': ['device', 'local-in-policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy6/{local-in-policy6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastpolicy': {
            'params': ['device', 'multicast-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-policy/{multicast-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastpolicy6': {
            'params': ['device', 'multicast-policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-policy6/{multicast-policy6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy/{policy}'
            ]
        },
        'firewall_proxypolicy': {
            'params': ['device', 'proxy-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-policy/{proxy-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_responseshapingpolicy': {
            'params': ['device', 'response-shaping-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/response-shaping-policy/{response-shaping-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_securitypolicy': {
            'params': ['device', 'security-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/security-policy/{security-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_service_category': {
            'params': ['category', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/service/category/{category}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_service_custom': {
            'params': ['custom', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/service/custom/{custom}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shapingpolicy': {
            'params': ['device', 'shaping-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-policy/{shaping-policy}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shapingprofile_shapingentries': {
            'params': ['device', 'shaping-entries', 'shaping-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sniffer': {
            'params': ['device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_ttlpolicy': {
            'params': ['device', 'ttl-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy/{ttl-policy}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_vip': {
            'params': ['device', 'vdom', 'vip'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip/{vip}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vip6': {
            'params': ['device', 'vdom', 'vip6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip6/{vip6}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'gtp_apnshaper': {
            'params': ['apn-shaper', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper/{apn-shaper}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'icap_localserver_icapservice': {
            'params': ['device', 'icap-service', 'local-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/local-server/{local-server}/icap-service/{icap-service}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'ips_sensor_entries': {
            'params': ['device', 'entries', 'sensor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'isolator_profile_entries': {
            'params': ['device', 'entries', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/isolator/profile/{profile}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'llm_server': {
            'params': ['device', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/llm/server/{server}'
            ],
            'v_range': [['7.6.5', '']]
        },
        'nsxt_servicechain_serviceindex': {
            'params': ['device', 'service-chain', 'service-index'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index/{service-index}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_bodyitem': {
            'params': ['body-item', 'device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_page_footer_footeritem': {
            'params': ['device', 'footer-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item/{footer-item}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_page_header_headeritem': {
            'params': ['device', 'header-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item/{header-item}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_policy6': {
            'params': ['device', 'policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6/{policy6}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'sshfilter_profile_shellcommands': {
            'params': ['device', 'profile', 'shell-commands', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['device', 'dynamic-port-policy', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationstitch_actions': {
            'params': ['actions', 'automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions/{actions}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_externalresource': {
            'params': ['device', 'external-resource', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/external-resource/{external-resource}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
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
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdnconnector_compartmentlist': {
            'params': ['compartment-list', 'device', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnconnector_externalaccountlist': {
            'params': ['device', 'external-account-list', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnconnector_forwardingrule': {
            'params': ['device', 'forwarding-rule', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnconnector_ociregionlist': {
            'params': ['device', 'oci-region-list', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnconnector_routetable': {
            'params': ['device', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdwan_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone/{zone}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_virtualwanlink_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwanlink_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwanlink_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'user_nacpolicy': {
            'params': ['device', 'nac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy/{nac-policy}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'videofilter_profile_filters': {
            'params': ['device', 'filters', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/profile/{profile}/filters/{filters}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': ['device', 'filters', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_ipsec_fec_mappings': {
            'params': ['device', 'fec', 'mappings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
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
        'vpnsslweb_portal_bookmarkgroup': {
            'params': ['bookmark-group', 'device', 'portal', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': ['bookmark-group', 'bookmarks', 'device', 'portal', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_splitdns': {
            'params': ['device', 'portal', 'split-dns', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_userbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webfilter_contentheader_entries': {
            'params': ['content-header', 'device', 'entries', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/content-header/{content-header}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_urlfilter_entries': {
            'params': ['device', 'entries', 'urlfilter', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_redirectprofile_entries': {
            'params': ['device', 'entries', 'redirect-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/redirect-profile/{redirect-profile}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_urllist_entries': {
            'params': ['device', 'entries', 'url-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-list/{url-list}/entries/{entries}'
            ],
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_urlmatch': {
            'params': ['device', 'url-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-match/{url-match}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv4-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv6-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile_commandlist': {
            'params': ['apcfg-profile', 'command-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile_policylist': {
            'params': ['bonjour-profile', 'device', 'policy-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup': {
            'params': ['device', 'mpsk-group', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup_mpskkey': {
            'params': ['device', 'mpsk-group', 'mpsk-key', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vap_vlanname': {
            'params': ['device', 'vap', 'vdom', 'vlan-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtp': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}'
            ],
            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
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
