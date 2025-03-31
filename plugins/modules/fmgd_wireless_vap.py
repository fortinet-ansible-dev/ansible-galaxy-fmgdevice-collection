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
module: fmgd_wireless_vap
short_description: Configure Virtual Access Points
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
    wireless_vap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            d80211k:
                aliases: ['80211k']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            d80211v:
                aliases: ['80211v']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            _centmgmt:
                type: str
                description: Centmgmt.
                choices:
                    - 'disable'
                    - 'enable'
            _dhcp_svr_id:
                type: list
                elements: str
                description: Dhcp svr id.
            _intf_allowaccess:
                type: list
                elements: str
                description: Intf allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'radius-acct'
                    - 'probe-response'
                    - 'capwap'
                    - 'dnp'
                    - 'ftm'
                    - 'fabric'
                    - 'speed-test'
            _intf_device_access_list:
                aliases: ['_intf_device-access-list']
                type: list
                elements: str
                description: Intf device access list.
            _intf_device_identification:
                aliases: ['_intf_device-identification']
                type: str
                description: Intf device identification.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_device_netscan:
                aliases: ['_intf_device-netscan']
                type: str
                description: Intf device netscan.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp_relay_ip:
                aliases: ['_intf_dhcp-relay-ip']
                type: list
                elements: str
                description: Intf dhcp relay ip.
            _intf_dhcp_relay_service:
                aliases: ['_intf_dhcp-relay-service']
                type: str
                description: Intf dhcp relay service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp_relay_type:
                aliases: ['_intf_dhcp-relay-type']
                type: str
                description: Intf dhcp relay type.
                choices:
                    - 'regular'
                    - 'ipsec'
            _intf_dhcp6_relay_ip:
                aliases: ['_intf_dhcp6-relay-ip']
                type: list
                elements: str
                description: Intf dhcp6 relay ip.
            _intf_dhcp6_relay_service:
                aliases: ['_intf_dhcp6-relay-service']
                type: str
                description: Intf dhcp6 relay service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp6_relay_type:
                aliases: ['_intf_dhcp6-relay-type']
                type: str
                description: Intf dhcp6 relay type.
                choices:
                    - 'regular'
            _intf_ip:
                type: list
                elements: str
                description: Support meta variable
            _intf_ip6_address:
                aliases: ['_intf_ip6-address']
                type: str
                description: Support meta variable
            _intf_ip6_allowaccess:
                aliases: ['_intf_ip6-allowaccess']
                type: list
                elements: str
                description: Intf ip6 allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'any'
                    - 'fgfm'
                    - 'capwap'
            _intf_listen_forticlient_connection:
                aliases: ['_intf_listen-forticlient-connection']
                type: str
                description: Intf listen forticlient connection.
                choices:
                    - 'disable'
                    - 'enable'
            _is_factory_setting:
                type: str
                description: Is factory setting.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'ext'
            access_control_list:
                aliases: ['access-control-list']
                type: list
                elements: str
                description: Profile name for access-control-list.
            additional_akms:
                aliases: ['additional-akms']
                type: list
                elements: str
                description: Additional AKMs.
                choices:
                    - 'akm6'
                    - 'akm24'
            address_group:
                aliases: ['address-group']
                type: list
                elements: str
                description: Firewall Address Group Name.
            address_group_policy:
                aliases: ['address-group-policy']
                type: str
                description: Configure MAC address filtering policy for MAC addresses that are in the address-group.
                choices:
                    - 'disable'
                    - 'allow'
                    - 'deny'
            akm24_only:
                aliases: ['akm24-only']
                type: str
                description: WPA3 SAE using group-dependent hash only
                choices:
                    - 'disable'
                    - 'enable'
            alias:
                type: str
                description: Alias.
            antivirus_profile:
                aliases: ['antivirus-profile']
                type: list
                elements: str
                description: AntiVirus profile name.
            application_detection_engine:
                aliases: ['application-detection-engine']
                type: str
                description: Enable/disable application detection engine
                choices:
                    - 'disable'
                    - 'enable'
            application_dscp_marking:
                aliases: ['application-dscp-marking']
                type: str
                description: Enable/disable application attribute based DSCP marking
                choices:
                    - 'disable'
                    - 'enable'
            application_list:
                aliases: ['application-list']
                type: list
                elements: str
                description: Application control list name.
            application_report_intv:
                aliases: ['application-report-intv']
                type: int
                description: Application report interval
            atf_weight:
                aliases: ['atf-weight']
                type: int
                description: Airtime weight in percentage
            auth:
                type: str
                description: Authentication protocol.
                choices:
                    - 'radius'
                    - 'usergroup'
                    - 'psk'
            auth_cert:
                aliases: ['auth-cert']
                type: list
                elements: str
                description: HTTPS server certificate.
            auth_portal_addr:
                aliases: ['auth-portal-addr']
                type: str
                description: Address of captive portal.
            beacon_advertising:
                aliases: ['beacon-advertising']
                type: list
                elements: str
                description: Fortinet beacon advertising IE data
                choices:
                    - 'name'
                    - 'model'
                    - 'serial-number'
            beacon_protection:
                aliases: ['beacon-protection']
                type: str
                description: Enable/disable beacon protection support
                choices:
                    - 'disable'
                    - 'enable'
            broadcast_ssid:
                aliases: ['broadcast-ssid']
                type: str
                description: Enable/disable broadcasting the SSID
                choices:
                    - 'disable'
                    - 'enable'
            broadcast_suppression:
                aliases: ['broadcast-suppression']
                type: list
                elements: str
                description: Optional suppression of broadcast messages.
                choices:
                    - 'dhcp'
                    - 'arp'
                    - 'dhcp2'
                    - 'arp2'
                    - 'netbios-ns'
                    - 'netbios-ds'
                    - 'arp3'
                    - 'dhcp-up'
                    - 'dhcp-down'
                    - 'arp-known'
                    - 'arp-unknown'
                    - 'arp-reply'
                    - 'ipv6'
                    - 'dhcp-starvation'
                    - 'arp-poison'
                    - 'all-other-mc'
                    - 'all-other-bc'
                    - 'arp-proxy'
                    - 'dhcp-ucast'
            bss_color_partial:
                aliases: ['bss-color-partial']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            bstm_disassociation_imminent:
                aliases: ['bstm-disassociation-imminent']
                type: str
                description: Enable/disable forcing of disassociation after the BSTM request timer has been reached
                choices:
                    - 'disable'
                    - 'enable'
            bstm_load_balancing_disassoc_timer:
                aliases: ['bstm-load-balancing-disassoc-timer']
                type: int
                description: Time interval for client to voluntarily leave AP before forcing a disassociation due to AP load-balancing
            bstm_rssi_disassoc_timer:
                aliases: ['bstm-rssi-disassoc-timer']
                type: int
                description: Time interval for client to voluntarily leave AP before forcing a disassociation due to low RSSI
            captive_portal:
                aliases: ['captive-portal']
                type: str
                description: Enable/disable captive portal.
                choices:
                    - 'disable'
                    - 'enable'
            captive_portal_ac_name:
                aliases: ['captive-portal-ac-name']
                type: str
                description: Local-bridging captive portal ac-name.
            captive_portal_auth_timeout:
                aliases: ['captive-portal-auth-timeout']
                type: int
                description: Hard timeout - AP will always clear the session after timeout regardless of traffic
            captive_portal_fw_accounting:
                aliases: ['captive-portal-fw-accounting']
                type: str
                description: Enable/disable RADIUS accounting for captive portal firewall authentication session.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_address_enforcement:
                aliases: ['dhcp-address-enforcement']
                type: str
                description: Enable/disable DHCP address enforcement
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_lease_time:
                aliases: ['dhcp-lease-time']
                type: int
                description: DHCP lease time in seconds for NAT IP address.
            dhcp_option43_insertion:
                aliases: ['dhcp-option43-insertion']
                type: str
                description: Enable/disable insertion of DHCP option 43
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_option82_circuit_id_insertion:
                aliases: ['dhcp-option82-circuit-id-insertion']
                type: str
                description: Enable/disable DHCP option 82 circuit-id insert
                choices:
                    - 'disable'
                    - 'style-1'
                    - 'style-2'
                    - 'style-3'
            dhcp_option82_insertion:
                aliases: ['dhcp-option82-insertion']
                type: str
                description: Enable/disable DHCP option 82 insert
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_option82_remote_id_insertion:
                aliases: ['dhcp-option82-remote-id-insertion']
                type: str
                description: Enable/disable DHCP option 82 remote-id insert
                choices:
                    - 'disable'
                    - 'style-1'
            dynamic_vlan:
                aliases: ['dynamic-vlan']
                type: str
                description: Enable/disable dynamic VLAN assignment.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    d80211k:
                        aliases: ['80211k']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    d80211v:
                        aliases: ['80211v']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    _centmgmt:
                        type: str
                        description: Centmgmt.
                        choices:
                            - 'disable'
                            - 'enable'
                    _dhcp_svr_id:
                        type: list
                        elements: str
                        description: Dhcp svr id.
                    _intf_allowaccess:
                        type: list
                        elements: str
                        description: Intf allowaccess.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'capwap'
                            - 'dnp'
                            - 'ftm'
                            - 'fabric'
                            - 'speed-test'
                    _intf_device_access_list:
                        aliases: ['_intf_device-access-list']
                        type: list
                        elements: str
                        description: Intf device access list.
                    _intf_device_identification:
                        aliases: ['_intf_device-identification']
                        type: str
                        description: Intf device identification.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_device_netscan:
                        aliases: ['_intf_device-netscan']
                        type: str
                        description: Intf device netscan.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp_relay_ip:
                        aliases: ['_intf_dhcp-relay-ip']
                        type: list
                        elements: str
                        description: Intf dhcp relay ip.
                    _intf_dhcp_relay_service:
                        aliases: ['_intf_dhcp-relay-service']
                        type: str
                        description: Intf dhcp relay service.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp_relay_type:
                        aliases: ['_intf_dhcp-relay-type']
                        type: str
                        description: Intf dhcp relay type.
                        choices:
                            - 'regular'
                            - 'ipsec'
                    _intf_dhcp6_relay_ip:
                        aliases: ['_intf_dhcp6-relay-ip']
                        type: list
                        elements: str
                        description: Intf dhcp6 relay ip.
                    _intf_dhcp6_relay_service:
                        aliases: ['_intf_dhcp6-relay-service']
                        type: str
                        description: Intf dhcp6 relay service.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp6_relay_type:
                        aliases: ['_intf_dhcp6-relay-type']
                        type: str
                        description: Intf dhcp6 relay type.
                        choices:
                            - 'regular'
                    _intf_ip:
                        type: list
                        elements: str
                        description: Support meta variable
                    _intf_ip6_address:
                        aliases: ['_intf_ip6-address']
                        type: str
                        description: Support meta variable
                    _intf_ip6_allowaccess:
                        aliases: ['_intf_ip6-allowaccess']
                        type: list
                        elements: str
                        description: Intf ip6 allowaccess.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'any'
                            - 'fgfm'
                            - 'capwap'
                    _intf_listen_forticlient_connection:
                        aliases: ['_intf_listen-forticlient-connection']
                        type: str
                        description: Intf listen forticlient connection.
                        choices:
                            - 'disable'
                            - 'enable'
                    _is_factory_setting:
                        type: str
                        description: Is factory setting.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'ext'
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    access_control_list:
                        aliases: ['access-control-list']
                        type: list
                        elements: str
                        description: Profile name for access-control-list.
                    acct_interim_interval:
                        aliases: ['acct-interim-interval']
                        type: int
                        description: WiFi RADIUS accounting interim interval
                    additional_akms:
                        aliases: ['additional-akms']
                        type: list
                        elements: str
                        description: Additional AKMs.
                        choices:
                            - 'akm6'
                            - 'akm24'
                    address_group:
                        aliases: ['address-group']
                        type: list
                        elements: str
                        description: Firewall Address Group Name.
                    address_group_policy:
                        aliases: ['address-group-policy']
                        type: str
                        description: Configure MAC address filtering policy for MAC addresses that are in the address-group.
                        choices:
                            - 'disable'
                            - 'allow'
                            - 'deny'
                    akm24_only:
                        aliases: ['akm24-only']
                        type: str
                        description: WPA3 SAE using group-dependent hash only
                        choices:
                            - 'disable'
                            - 'enable'
                    alias:
                        type: str
                        description: Alias.
                    antivirus_profile:
                        aliases: ['antivirus-profile']
                        type: list
                        elements: str
                        description: AntiVirus profile name.
                    application_detection_engine:
                        aliases: ['application-detection-engine']
                        type: str
                        description: Enable/disable application detection engine
                        choices:
                            - 'disable'
                            - 'enable'
                    application_dscp_marking:
                        aliases: ['application-dscp-marking']
                        type: str
                        description: Enable/disable application attribute based DSCP marking
                        choices:
                            - 'disable'
                            - 'enable'
                    application_list:
                        aliases: ['application-list']
                        type: list
                        elements: str
                        description: Application control list name.
                    application_report_intv:
                        aliases: ['application-report-intv']
                        type: int
                        description: Application report interval
                    atf_weight:
                        aliases: ['atf-weight']
                        type: int
                        description: Airtime weight in percentage
                    auth:
                        type: str
                        description: Authentication protocol.
                        choices:
                            - 'radius'
                            - 'usergroup'
                            - 'psk'
                    auth_cert:
                        aliases: ['auth-cert']
                        type: list
                        elements: str
                        description: HTTPS server certificate.
                    auth_portal_addr:
                        aliases: ['auth-portal-addr']
                        type: str
                        description: Address of captive portal.
                    beacon_advertising:
                        aliases: ['beacon-advertising']
                        type: list
                        elements: str
                        description: Fortinet beacon advertising IE data
                        choices:
                            - 'name'
                            - 'model'
                            - 'serial-number'
                    beacon_protection:
                        aliases: ['beacon-protection']
                        type: str
                        description: Enable/disable beacon protection support
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast_ssid:
                        aliases: ['broadcast-ssid']
                        type: str
                        description: Enable/disable broadcasting the SSID
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast_suppression:
                        aliases: ['broadcast-suppression']
                        type: list
                        elements: str
                        description: Optional suppression of broadcast messages.
                        choices:
                            - 'dhcp'
                            - 'arp'
                            - 'dhcp2'
                            - 'arp2'
                            - 'netbios-ns'
                            - 'netbios-ds'
                            - 'arp3'
                            - 'dhcp-up'
                            - 'dhcp-down'
                            - 'arp-known'
                            - 'arp-unknown'
                            - 'arp-reply'
                            - 'ipv6'
                            - 'dhcp-starvation'
                            - 'arp-poison'
                            - 'all-other-mc'
                            - 'all-other-bc'
                            - 'arp-proxy'
                            - 'dhcp-ucast'
                    bss_color_partial:
                        aliases: ['bss-color-partial']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    bstm_disassociation_imminent:
                        aliases: ['bstm-disassociation-imminent']
                        type: str
                        description: Enable/disable forcing of disassociation after the BSTM request timer has been reached
                        choices:
                            - 'disable'
                            - 'enable'
                    bstm_load_balancing_disassoc_timer:
                        aliases: ['bstm-load-balancing-disassoc-timer']
                        type: int
                        description: Time interval for client to voluntarily leave AP before forcing a disassociation due to AP load-balancing
                    bstm_rssi_disassoc_timer:
                        aliases: ['bstm-rssi-disassoc-timer']
                        type: int
                        description: Time interval for client to voluntarily leave AP before forcing a disassociation due to low RSSI
                    captive_portal:
                        aliases: ['captive-portal']
                        type: str
                        description: Enable/disable captive portal.
                        choices:
                            - 'disable'
                            - 'enable'
                    captive_portal_ac_name:
                        aliases: ['captive-portal-ac-name']
                        type: str
                        description: Local-bridging captive portal ac-name.
                    captive_portal_auth_timeout:
                        aliases: ['captive-portal-auth-timeout']
                        type: int
                        description: Hard timeout - AP will always clear the session after timeout regardless of traffic
                    captive_portal_fw_accounting:
                        aliases: ['captive-portal-fw-accounting']
                        type: str
                        description: Enable/disable RADIUS accounting for captive portal firewall authentication session.
                        choices:
                            - 'disable'
                            - 'enable'
                    captive_portal_macauth_radius_secret:
                        aliases: ['captive-portal-macauth-radius-secret']
                        type: list
                        elements: str
                        description: Secret key to access the macauth RADIUS server.
                    captive_portal_macauth_radius_server:
                        aliases: ['captive-portal-macauth-radius-server']
                        type: str
                        description: Captive portal external RADIUS server domain name or IP address.
                    captive_portal_radius_secret:
                        aliases: ['captive-portal-radius-secret']
                        type: list
                        elements: str
                        description: Secret key to access the RADIUS server.
                    captive_portal_radius_server:
                        aliases: ['captive-portal-radius-server']
                        type: str
                        description: Captive portal RADIUS server domain name or IP address.
                    captive_portal_session_timeout_interval:
                        aliases: ['captive-portal-session-timeout-interval']
                        type: int
                        description: Session timeout interval
                    client_count:
                        aliases: ['client-count']
                        type: int
                        description: Client count.
                    dhcp_address_enforcement:
                        aliases: ['dhcp-address-enforcement']
                        type: str
                        description: Enable/disable DHCP address enforcement
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_lease_time:
                        aliases: ['dhcp-lease-time']
                        type: int
                        description: DHCP lease time in seconds for NAT IP address.
                    dhcp_option43_insertion:
                        aliases: ['dhcp-option43-insertion']
                        type: str
                        description: Enable/disable insertion of DHCP option 43
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_option82_circuit_id_insertion:
                        aliases: ['dhcp-option82-circuit-id-insertion']
                        type: str
                        description: Enable/disable DHCP option 82 circuit-id insert
                        choices:
                            - 'disable'
                            - 'style-1'
                            - 'style-2'
                            - 'style-3'
                    dhcp_option82_insertion:
                        aliases: ['dhcp-option82-insertion']
                        type: str
                        description: Enable/disable DHCP option 82 insert
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_option82_remote_id_insertion:
                        aliases: ['dhcp-option82-remote-id-insertion']
                        type: str
                        description: Enable/disable DHCP option 82 remote-id insert
                        choices:
                            - 'disable'
                            - 'style-1'
                    dynamic_vlan:
                        aliases: ['dynamic-vlan']
                        type: str
                        description: Enable/disable dynamic VLAN assignment.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_reauth:
                        aliases: ['eap-reauth']
                        type: str
                        description: Enable/disable EAP re-authentication for WPA-Enterprise security.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_reauth_intv:
                        aliases: ['eap-reauth-intv']
                        type: int
                        description: EAP re-authentication interval
                    eapol_key_retries:
                        aliases: ['eapol-key-retries']
                        type: str
                        description: Enable/disable retransmission of EAPOL-Key frames
                        choices:
                            - 'disable'
                            - 'enable'
                    encrypt:
                        type: str
                        description: Encryption protocol to use
                        choices:
                            - 'TKIP'
                            - 'AES'
                            - 'TKIP-AES'
                    external_fast_roaming:
                        aliases: ['external-fast-roaming']
                        type: str
                        description: Enable/disable fast roaming or pre-authentication with external APs not managed by the FortiGate
                        choices:
                            - 'disable'
                            - 'enable'
                    external_logout:
                        aliases: ['external-logout']
                        type: str
                        description: URL of external authentication logout server.
                    external_web:
                        aliases: ['external-web']
                        type: str
                        description: URL of external authentication web server.
                    external_web_format:
                        aliases: ['external-web-format']
                        type: str
                        description: URL query parameter detection
                        choices:
                            - 'auto-detect'
                            - 'no-query-string'
                            - 'partial-query-string'
                    fast_bss_transition:
                        aliases: ['fast-bss-transition']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    fast_roaming:
                        aliases: ['fast-roaming']
                        type: str
                        description: Enable/disable fast-roaming, or pre-authentication, where supported by clients
                        choices:
                            - 'disable'
                            - 'enable'
                    ft_mobility_domain:
                        aliases: ['ft-mobility-domain']
                        type: int
                        description: Mobility domain identifier in FT
                    ft_over_ds:
                        aliases: ['ft-over-ds']
                        type: str
                        description: Enable/disable FT over the Distribution System
                        choices:
                            - 'disable'
                            - 'enable'
                    ft_r0_key_lifetime:
                        aliases: ['ft-r0-key-lifetime']
                        type: int
                        description: Lifetime of the PMK-R0 key in FT, 1-65535 minutes.
                    gas_comeback_delay:
                        aliases: ['gas-comeback-delay']
                        type: int
                        description: GAS comeback delay
                    gas_fragmentation_limit:
                        aliases: ['gas-fragmentation-limit']
                        type: int
                        description: GAS fragmentation limit
                    gtk_rekey:
                        aliases: ['gtk-rekey']
                        type: str
                        description: Enable/disable GTK rekey for WPA security.
                        choices:
                            - 'disable'
                            - 'enable'
                    gtk_rekey_intv:
                        aliases: ['gtk-rekey-intv']
                        type: int
                        description: GTK rekey interval
                    high_efficiency:
                        aliases: ['high-efficiency']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    hotspot20_profile:
                        aliases: ['hotspot20-profile']
                        type: list
                        elements: str
                        description: Hotspot 2.
                    igmp_snooping:
                        aliases: ['igmp-snooping']
                        type: str
                        description: Enable/disable IGMP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    intra_vap_privacy:
                        aliases: ['intra-vap-privacy']
                        type: str
                        description: Enable/disable blocking communication between clients on the same SSID
                        choices:
                            - 'disable'
                            - 'enable'
                    ip:
                        type: list
                        elements: str
                        description: IP address and subnet mask for the local standalone NAT subnet.
                    ips_sensor:
                        aliases: ['ips-sensor']
                        type: list
                        elements: str
                        description: IPS sensor name.
                    ipv6_rules:
                        aliases: ['ipv6-rules']
                        type: list
                        elements: str
                        description: Optional rules of IPv6 packets.
                        choices:
                            - 'drop-icmp6ra'
                            - 'drop-icmp6rs'
                            - 'drop-llmnr6'
                            - 'drop-icmp6mld2'
                            - 'drop-dhcp6s'
                            - 'drop-dhcp6c'
                            - 'ndp-proxy'
                            - 'drop-ns-dad'
                            - 'drop-ns-nondad'
                    key:
                        type: list
                        elements: str
                        description: WEP Key.
                    keyindex:
                        type: int
                        description: WEP key index
                    l3_roaming:
                        aliases: ['l3-roaming']
                        type: str
                        description: Enable/disable layer 3 roaming
                        choices:
                            - 'disable'
                            - 'enable'
                    l3_roaming_mode:
                        aliases: ['l3-roaming-mode']
                        type: str
                        description: Select the way that layer 3 roaming traffic is passed
                        choices:
                            - 'direct'
                            - 'indirect'
                    ldpc:
                        type: str
                        description: VAP low-density parity-check
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'rxtx'
                    local_authentication:
                        aliases: ['local-authentication']
                        type: str
                        description: Enable/disable AP local authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_bridging:
                        aliases: ['local-bridging']
                        type: str
                        description: Enable/disable bridging of wireless and Ethernet interfaces on the FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                    local_lan:
                        aliases: ['local-lan']
                        type: str
                        description: Allow/deny traffic destined for a Class A, B, or C private IP address
                        choices:
                            - 'deny'
                            - 'allow'
                    local_standalone:
                        aliases: ['local-standalone']
                        type: str
                        description: Enable/disable AP local standalone
                        choices:
                            - 'disable'
                            - 'enable'
                    local_standalone_dns:
                        aliases: ['local-standalone-dns']
                        type: str
                        description: Enable/disable AP local standalone DNS.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_standalone_dns_ip:
                        aliases: ['local-standalone-dns-ip']
                        type: list
                        elements: str
                        description: IPv4 addresses for the local standalone DNS.
                    local_standalone_nat:
                        aliases: ['local-standalone-nat']
                        type: str
                        description: Enable/disable AP local standalone NAT mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_switching:
                        aliases: ['local-switching']
                        type: str
                        description: Local switching.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_auth_bypass:
                        aliases: ['mac-auth-bypass']
                        type: str
                        description: Enable/disable MAC authentication bypass.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_called_station_delimiter:
                        aliases: ['mac-called-station-delimiter']
                        type: str
                        description: MAC called station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_calling_station_delimiter:
                        aliases: ['mac-calling-station-delimiter']
                        type: str
                        description: MAC calling station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_case:
                        aliases: ['mac-case']
                        type: str
                        description: MAC case
                        choices:
                            - 'uppercase'
                            - 'lowercase'
                    mac_filter:
                        aliases: ['mac-filter']
                        type: str
                        description: Enable/disable MAC filtering to block wireless clients by mac address.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_filter_policy_other:
                        aliases: ['mac-filter-policy-other']
                        type: str
                        description: Allow or block clients with MAC addresses that are not in the filter list.
                        choices:
                            - 'deny'
                            - 'allow'
                    mac_password_delimiter:
                        aliases: ['mac-password-delimiter']
                        type: str
                        description: MAC authentication password delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_username_delimiter:
                        aliases: ['mac-username-delimiter']
                        type: str
                        description: MAC authentication username delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    max_clients:
                        aliases: ['max-clients']
                        type: int
                        description: Maximum number of clients that can connect simultaneously to the VAP
                    max_clients_ap:
                        aliases: ['max-clients-ap']
                        type: int
                        description: Maximum number of clients that can connect simultaneously to the VAP per AP radio
                    mbo:
                        type: str
                        description: Enable/disable Multiband Operation
                        choices:
                            - 'disable'
                            - 'enable'
                    mbo_cell_data_conn_pref:
                        aliases: ['mbo-cell-data-conn-pref']
                        type: str
                        description: MBO cell data connection preference
                        choices:
                            - 'excluded'
                            - 'prefer-not'
                            - 'prefer-use'
                    me_disable_thresh:
                        aliases: ['me-disable-thresh']
                        type: int
                        description: Disable multicast enhancement when this many clients are receiving multicast traffic.
                    mesh_backhaul:
                        aliases: ['mesh-backhaul']
                        type: str
                        description: Enable/disable using this VAP as a WiFi mesh backhaul
                        choices:
                            - 'disable'
                            - 'enable'
                    mpsk:
                        type: str
                        description: Enable/disable multiple PSK authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    mpsk_concurrent_clients:
                        aliases: ['mpsk-concurrent-clients']
                        type: int
                        description: Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication
                    mpsk_profile:
                        aliases: ['mpsk-profile']
                        type: list
                        elements: str
                        description: MPSK profile name.
                    mu_mimo:
                        aliases: ['mu-mimo']
                        type: str
                        description: Enable/disable Multi-user MIMO
                        choices:
                            - 'disable'
                            - 'enable'
                    multicast_enhance:
                        aliases: ['multicast-enhance']
                        type: str
                        description: Enable/disable converting multicast to unicast to improve performance
                        choices:
                            - 'disable'
                            - 'enable'
                    multicast_rate:
                        aliases: ['multicast-rate']
                        type: str
                        description: Multicast rate
                        choices:
                            - '0'
                            - '6000'
                            - '12000'
                            - '24000'
                    nac:
                        type: str
                        description: Enable/disable network access control.
                        choices:
                            - 'disable'
                            - 'enable'
                    nac_profile:
                        aliases: ['nac-profile']
                        type: list
                        elements: str
                        description: NAC profile name.
                    nas_filter_rule:
                        aliases: ['nas-filter-rule']
                        type: str
                        description: Enable/disable NAS filter rule support
                        choices:
                            - 'disable'
                            - 'enable'
                    neighbor_report_dual_band:
                        aliases: ['neighbor-report-dual-band']
                        type: str
                        description: Enable/disable dual-band neighbor report
                        choices:
                            - 'disable'
                            - 'enable'
                    okc:
                        type: str
                        description: Enable/disable Opportunistic Key Caching
                        choices:
                            - 'disable'
                            - 'enable'
                    osen:
                        type: str
                        description: Enable/disable OSEN as part of key management
                        choices:
                            - 'disable'
                            - 'enable'
                    owe_groups:
                        aliases: ['owe-groups']
                        type: list
                        elements: str
                        description: OWE-Groups.
                        choices:
                            - '19'
                            - '20'
                            - '21'
                    owe_transition:
                        aliases: ['owe-transition']
                        type: str
                        description: Enable/disable OWE transition mode support.
                        choices:
                            - 'disable'
                            - 'enable'
                    owe_transition_ssid:
                        aliases: ['owe-transition-ssid']
                        type: str
                        description: OWE transition mode peer SSID.
                    passphrase:
                        type: list
                        elements: str
                        description: WPA pre-shared key
                    pmf:
                        type: str
                        description: Protected Management Frames
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'optional'
                    pmf_assoc_comeback_timeout:
                        aliases: ['pmf-assoc-comeback-timeout']
                        type: int
                        description: Protected Management Frames
                    pmf_sa_query_retry_timeout:
                        aliases: ['pmf-sa-query-retry-timeout']
                        type: int
                        description: Protected Management Frames
                    port_macauth:
                        aliases: ['port-macauth']
                        type: str
                        description: Enable/disable LAN port MAC authentication
                        choices:
                            - 'disable'
                            - 'radius'
                            - 'address-group'
                    port_macauth_reauth_timeout:
                        aliases: ['port-macauth-reauth-timeout']
                        type: int
                        description: LAN port MAC authentication re-authentication timeout value
                    port_macauth_timeout:
                        aliases: ['port-macauth-timeout']
                        type: int
                        description: LAN port MAC authentication idle timeout value
                    portal_message_override_group:
                        aliases: ['portal-message-override-group']
                        type: list
                        elements: str
                        description: Replacement message group for this VAP
                    portal_type:
                        aliases: ['portal-type']
                        type: str
                        description: Captive portal functionality.
                        choices:
                            - 'auth'
                            - 'auth+disclaimer'
                            - 'disclaimer'
                            - 'email-collect'
                            - 'cmcc'
                            - 'cmcc-macauth'
                            - 'auth-mac'
                            - 'external-auth'
                            - 'external-macauth'
                    primary_wag_profile:
                        aliases: ['primary-wag-profile']
                        type: list
                        elements: str
                        description: Primary wireless access gateway profile name.
                    probe_resp_suppression:
                        aliases: ['probe-resp-suppression']
                        type: str
                        description: Enable/disable probe response suppression
                        choices:
                            - 'disable'
                            - 'enable'
                    probe_resp_threshold:
                        aliases: ['probe-resp-threshold']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the AP response to probe requests
                    ptk_rekey:
                        aliases: ['ptk-rekey']
                        type: str
                        description: Enable/disable PTK rekey for WPA-Enterprise security.
                        choices:
                            - 'disable'
                            - 'enable'
                    ptk_rekey_intv:
                        aliases: ['ptk-rekey-intv']
                        type: int
                        description: PTK rekey interval
                    qos_profile:
                        aliases: ['qos-profile']
                        type: list
                        elements: str
                        description: Quality of service profile name.
                    quarantine:
                        type: str
                        description: Enable/disable station quarantine
                        choices:
                            - 'disable'
                            - 'enable'
                    radio_2g_threshold:
                        aliases: ['radio-2g-threshold']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the AP response to receive a packet in 2.
                    radio_5g_threshold:
                        aliases: ['radio-5g-threshold']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the AP response to receive a packet in 5G band
                    radio_sensitivity:
                        aliases: ['radio-sensitivity']
                        type: str
                        description: Enable/disable software radio sensitivity
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_mac_auth:
                        aliases: ['radius-mac-auth']
                        type: str
                        description: Enable/disable RADIUS-based MAC authentication of clients
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_mac_auth_block_interval:
                        aliases: ['radius-mac-auth-block-interval']
                        type: int
                        description: Dont send RADIUS MAC auth request again if the client has been rejected within specific interval
                    radius_mac_auth_server:
                        aliases: ['radius-mac-auth-server']
                        type: list
                        elements: str
                        description: RADIUS-based MAC authentication server.
                    radius_mac_auth_usergroups:
                        aliases: ['radius-mac-auth-usergroups']
                        type: list
                        elements: str
                        description: Selective user groups that are permitted for RADIUS mac authentication.
                    radius_mac_mpsk_auth:
                        aliases: ['radius-mac-mpsk-auth']
                        type: str
                        description: Enable/disable RADIUS-based MAC authentication of clients for MPSK authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_mac_mpsk_timeout:
                        aliases: ['radius-mac-mpsk-timeout']
                        type: int
                        description: RADIUS MAC MPSK cache timeout interval
                    radius_server:
                        aliases: ['radius-server']
                        type: list
                        elements: str
                        description: RADIUS server to be used to authenticate WiFi users.
                    rates_11a:
                        aliases: ['rates-11a']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - '1'
                            - '1-basic'
                            - '2'
                            - '2-basic'
                            - '5.5'
                            - '5.5-basic'
                            - '6'
                            - '6-basic'
                            - '9'
                            - '9-basic'
                            - '12'
                            - '12-basic'
                            - '18'
                            - '18-basic'
                            - '24'
                            - '24-basic'
                            - '36'
                            - '36-basic'
                            - '48'
                            - '48-basic'
                            - '54'
                            - '54-basic'
                            - '11'
                            - '11-basic'
                    rates_11ac_mcs_map:
                        aliases: ['rates-11ac-mcs-map']
                        type: str
                        description: Comma separated list of max supported VHT MCS for spatial streams 1 through 8.
                    rates_11ac_ss12:
                        aliases: ['rates-11ac-ss12']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/1'
                            - 'mcs9/1'
                            - 'mcs0/2'
                            - 'mcs1/2'
                            - 'mcs2/2'
                            - 'mcs3/2'
                            - 'mcs4/2'
                            - 'mcs5/2'
                            - 'mcs6/2'
                            - 'mcs7/2'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/1'
                            - 'mcs11/1'
                            - 'mcs10/2'
                            - 'mcs11/2'
                    rates_11ac_ss34:
                        aliases: ['rates-11ac-ss34']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs0/3'
                            - 'mcs1/3'
                            - 'mcs2/3'
                            - 'mcs3/3'
                            - 'mcs4/3'
                            - 'mcs5/3'
                            - 'mcs6/3'
                            - 'mcs7/3'
                            - 'mcs8/3'
                            - 'mcs9/3'
                            - 'mcs0/4'
                            - 'mcs1/4'
                            - 'mcs2/4'
                            - 'mcs3/4'
                            - 'mcs4/4'
                            - 'mcs5/4'
                            - 'mcs6/4'
                            - 'mcs7/4'
                            - 'mcs8/4'
                            - 'mcs9/4'
                            - 'mcs10/3'
                            - 'mcs11/3'
                            - 'mcs10/4'
                            - 'mcs11/4'
                    rates_11ax_mcs_map:
                        aliases: ['rates-11ax-mcs-map']
                        type: str
                        description: Comma separated list of max supported HE MCS for spatial streams 1 through 8.
                    rates_11ax_ss12:
                        aliases: ['rates-11ax-ss12']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/1'
                            - 'mcs9/1'
                            - 'mcs10/1'
                            - 'mcs11/1'
                            - 'mcs0/2'
                            - 'mcs1/2'
                            - 'mcs2/2'
                            - 'mcs3/2'
                            - 'mcs4/2'
                            - 'mcs5/2'
                            - 'mcs6/2'
                            - 'mcs7/2'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/2'
                            - 'mcs11/2'
                    rates_11ax_ss34:
                        aliases: ['rates-11ax-ss34']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs0/3'
                            - 'mcs1/3'
                            - 'mcs2/3'
                            - 'mcs3/3'
                            - 'mcs4/3'
                            - 'mcs5/3'
                            - 'mcs6/3'
                            - 'mcs7/3'
                            - 'mcs8/3'
                            - 'mcs9/3'
                            - 'mcs10/3'
                            - 'mcs11/3'
                            - 'mcs0/4'
                            - 'mcs1/4'
                            - 'mcs2/4'
                            - 'mcs3/4'
                            - 'mcs4/4'
                            - 'mcs5/4'
                            - 'mcs6/4'
                            - 'mcs7/4'
                            - 'mcs8/4'
                            - 'mcs9/4'
                            - 'mcs10/4'
                            - 'mcs11/4'
                    rates_11be_mcs_map:
                        aliases: ['rates-11be-mcs-map']
                        type: str
                        description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 20MHz/40MHz/80MHz bandwidth.
                    rates_11be_mcs_map_160:
                        aliases: ['rates-11be-mcs-map-160']
                        type: str
                        description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 160MHz bandwidth.
                    rates_11be_mcs_map_320:
                        aliases: ['rates-11be-mcs-map-320']
                        type: str
                        description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 320MHz bandwidth.
                    rates_11bg:
                        aliases: ['rates-11bg']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - '1'
                            - '1-basic'
                            - '2'
                            - '2-basic'
                            - '5.5'
                            - '5.5-basic'
                            - '6'
                            - '6-basic'
                            - '9'
                            - '9-basic'
                            - '12'
                            - '12-basic'
                            - '18'
                            - '18-basic'
                            - '24'
                            - '24-basic'
                            - '36'
                            - '36-basic'
                            - '48'
                            - '48-basic'
                            - '54'
                            - '54-basic'
                            - '11'
                            - '11-basic'
                    rates_11n_ss12:
                        aliases: ['rates-11n-ss12']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/2'
                            - 'mcs11/2'
                            - 'mcs12/2'
                            - 'mcs13/2'
                            - 'mcs14/2'
                            - 'mcs15/2'
                    rates_11n_ss34:
                        aliases: ['rates-11n-ss34']
                        type: list
                        elements: str
                        description: Allowed data rates for 802.
                        choices:
                            - 'mcs16/3'
                            - 'mcs17/3'
                            - 'mcs18/3'
                            - 'mcs19/3'
                            - 'mcs20/3'
                            - 'mcs21/3'
                            - 'mcs22/3'
                            - 'mcs23/3'
                            - 'mcs24/4'
                            - 'mcs25/4'
                            - 'mcs26/4'
                            - 'mcs27/4'
                            - 'mcs28/4'
                            - 'mcs29/4'
                            - 'mcs30/4'
                            - 'mcs31/4'
                    roaming_acct_interim_update:
                        aliases: ['roaming-acct-interim-update']
                        type: str
                        description: Enable/disable using accounting interim update instead of accounting start/stop on roaming for WPA-Enterprise secu...
                        choices:
                            - 'disable'
                            - 'enable'
                    sae_groups:
                        aliases: ['sae-groups']
                        type: list
                        elements: str
                        description: SAE-Groups.
                        choices:
                            - '1'
                            - '2'
                            - '5'
                            - '14'
                            - '15'
                            - '16'
                            - '17'
                            - '18'
                            - '19'
                            - '20'
                            - '21'
                            - '27'
                            - '28'
                            - '29'
                            - '30'
                            - '31'
                    sae_h2e_only:
                        aliases: ['sae-h2e-only']
                        type: str
                        description: Use hash-to-element-only mechanism for PWE derivation
                        choices:
                            - 'disable'
                            - 'enable'
                    sae_hnp_only:
                        aliases: ['sae-hnp-only']
                        type: str
                        description: Use hunting-and-pecking-only mechanism for PWE derivation
                        choices:
                            - 'disable'
                            - 'enable'
                    sae_password:
                        aliases: ['sae-password']
                        type: list
                        elements: str
                        description: WPA3 SAE password to be used to authenticate WiFi users.
                    sae_pk:
                        aliases: ['sae-pk']
                        type: str
                        description: Enable/disable WPA3 SAE-PK
                        choices:
                            - 'disable'
                            - 'enable'
                    sae_private_key:
                        aliases: ['sae-private-key']
                        type: str
                        description: Private key used for WPA3 SAE-PK authentication.
                    scan_botnet_connections:
                        aliases: ['scan-botnet-connections']
                        type: str
                        description: Block or monitor connections to Botnet servers or disable Botnet scanning.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    schedule:
                        type: list
                        elements: str
                        description: Firewall schedules for enabling this VAP on the FortiAP.
                    secondary_wag_profile:
                        aliases: ['secondary-wag-profile']
                        type: list
                        elements: str
                        description: Secondary wireless access gateway profile name.
                    security:
                        type: str
                        description: Security mode for the wireless interface
                        choices:
                            - 'None'
                            - 'wep64'
                            - 'wep128'
                            - 'WPA_PSK'
                            - 'WPA_RADIUS'
                            - 'WPA'
                            - 'WPA2'
                            - 'WPA2_AUTO'
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'captive-portal'
                            - 'wpa-only-personal'
                            - 'wpa-only-enterprise'
                            - 'wpa2-only-personal'
                            - 'wpa2-only-enterprise'
                            - 'wpa-personal+captive-portal'
                            - 'wpa-only-personal+captive-portal'
                            - 'wpa2-only-personal+captive-portal'
                            - 'osen'
                            - 'wpa3-enterprise'
                            - 'sae'
                            - 'sae-transition'
                            - 'owe'
                            - 'wpa3-sae'
                            - 'wpa3-sae-transition'
                            - 'wpa3-only-enterprise'
                            - 'wpa3-enterprise-transition'
                    security_exempt_list:
                        aliases: ['security-exempt-list']
                        type: list
                        elements: str
                        description: Optional security exempt list for captive portal authentication.
                    security_obsolete_option:
                        aliases: ['security-obsolete-option']
                        type: str
                        description: Enable/disable obsolete security options.
                        choices:
                            - 'disable'
                            - 'enable'
                    security_redirect_url:
                        aliases: ['security-redirect-url']
                        type: str
                        description: Optional URL for redirecting users after they pass captive portal authentication.
                    selected_usergroups:
                        aliases: ['selected-usergroups']
                        type: list
                        elements: str
                        description: Selective user groups that are permitted to authenticate.
                    split_tunneling:
                        aliases: ['split-tunneling']
                        type: str
                        description: Enable/disable split tunneling
                        choices:
                            - 'disable'
                            - 'enable'
                    ssid:
                        type: str
                        description: IEEE 802.
                    sticky_client_remove:
                        aliases: ['sticky-client-remove']
                        type: str
                        description: Enable/disable sticky client remove to maintain good signal level clients in SSID
                        choices:
                            - 'disable'
                            - 'enable'
                    sticky_client_threshold_2g:
                        aliases: ['sticky-client-threshold-2g']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the 2G client to be serviced by the AP
                    sticky_client_threshold_5g:
                        aliases: ['sticky-client-threshold-5g']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the 5G client to be serviced by the AP
                    sticky_client_threshold_6g:
                        aliases: ['sticky-client-threshold-6g']
                        type: str
                        description: Minimum signal level/threshold in dBm required for the 6G client to be serviced by the AP
                    target_wake_time:
                        aliases: ['target-wake-time']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    tkip_counter_measure:
                        aliases: ['tkip-counter-measure']
                        type: str
                        description: Enable/disable TKIP counter measure.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel_echo_interval:
                        aliases: ['tunnel-echo-interval']
                        type: int
                        description: The time interval to send echo to both primary and secondary tunnel peers
                    tunnel_fallback_interval:
                        aliases: ['tunnel-fallback-interval']
                        type: int
                        description: The time interval for secondary tunnel to fall back to primary tunnel
                    usergroup:
                        type: list
                        elements: str
                        description: Firewall user group to be used to authenticate WiFi users.
                    utm_log:
                        aliases: ['utm-log']
                        type: str
                        description: Enable/disable UTM logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    utm_profile:
                        aliases: ['utm-profile']
                        type: list
                        elements: str
                        description: UTM profile name.
                    utm_status:
                        aliases: ['utm-status']
                        type: str
                        description: Enable to add one or more security profiles
                        choices:
                            - 'disable'
                            - 'enable'
                    vdom:
                        type: list
                        elements: str
                        description: Vdom.
                    vlan_auto:
                        aliases: ['vlan-auto']
                        type: str
                        description: Enable/disable automatic management of SSID VLAN interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlan_pooling:
                        aliases: ['vlan-pooling']
                        type: str
                        description: Enable/disable VLAN pooling, to allow grouping of multiple wireless controller VLANs into VLAN pools
                        choices:
                            - 'wtp-group'
                            - 'round-robin'
                            - 'hash'
                            - 'disable'
                    vlanid:
                        type: int
                        description: Optional VLAN ID.
                    voice_enterprise:
                        aliases: ['voice-enterprise']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    webfilter_profile:
                        aliases: ['webfilter-profile']
                        type: list
                        elements: str
                        description: WebFilter profile name.
                    _intf_ip_managed_by_fortiipam:
                        aliases: ['_intf_ip-managed-by-fortiipam']
                        type: str
                        description: Intf ip managed by fortiipam.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'inherit-global'
                    _intf_managed_subnetwork_size:
                        aliases: ['_intf_managed-subnetwork-size']
                        type: str
                        description: Intf managed subnetwork size.
                        choices:
                            - '32'
                            - '64'
                            - '128'
                            - '256'
                            - '512'
                            - '1024'
                            - '2048'
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                            - '65536'
                    domain_name_stripping:
                        aliases: ['domain-name-stripping']
                        type: str
                        description: Enable/disable stripping domain name from identity
                        choices:
                            - 'disable'
                            - 'enable'
                    local_lan_partition:
                        aliases: ['local-lan-partition']
                        type: str
                        description: Enable/disable segregating client traffic to local LAN side
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_role:
                        type: str
                        description: Intf role.
                        choices:
                            - 'lan'
                            - 'wan'
                            - 'dmz'
                            - 'undefined'
                    called_station_id_type:
                        aliases: ['called-station-id-type']
                        type: str
                        description: The format type of RADIUS attribute Called-Station-Id
                        choices:
                            - 'mac'
                            - 'ip'
                            - 'apname'
                    external_pre_auth:
                        aliases: ['external-pre-auth']
                        type: str
                        description: Enable/disable pre-authentication with external APs not managed by the FortiGate
                        choices:
                            - 'disable'
                            - 'enable'
                    pre_auth:
                        aliases: ['pre-auth']
                        type: str
                        description: Enable/disable pre-authentication, where supported by clients
                        choices:
                            - 'disable'
                            - 'enable'
            eap_reauth:
                aliases: ['eap-reauth']
                type: str
                description: Enable/disable EAP re-authentication for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            eap_reauth_intv:
                aliases: ['eap-reauth-intv']
                type: int
                description: EAP re-authentication interval
            eapol_key_retries:
                aliases: ['eapol-key-retries']
                type: str
                description: Enable/disable retransmission of EAPOL-Key frames
                choices:
                    - 'disable'
                    - 'enable'
            encrypt:
                type: str
                description: Encryption protocol to use
                choices:
                    - 'TKIP'
                    - 'AES'
                    - 'TKIP-AES'
            external_fast_roaming:
                aliases: ['external-fast-roaming']
                type: str
                description: Enable/disable fast roaming or pre-authentication with external APs not managed by the FortiGate
                choices:
                    - 'disable'
                    - 'enable'
            external_logout:
                aliases: ['external-logout']
                type: str
                description: URL of external authentication logout server.
            external_web:
                aliases: ['external-web']
                type: str
                description: URL of external authentication web server.
            external_web_format:
                aliases: ['external-web-format']
                type: str
                description: URL query parameter detection
                choices:
                    - 'auto-detect'
                    - 'no-query-string'
                    - 'partial-query-string'
            fast_bss_transition:
                aliases: ['fast-bss-transition']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            fast_roaming:
                aliases: ['fast-roaming']
                type: str
                description: Enable/disable fast-roaming, or pre-authentication, where supported by clients
                choices:
                    - 'disable'
                    - 'enable'
            ft_mobility_domain:
                aliases: ['ft-mobility-domain']
                type: int
                description: Mobility domain identifier in FT
            ft_over_ds:
                aliases: ['ft-over-ds']
                type: str
                description: Enable/disable FT over the Distribution System
                choices:
                    - 'disable'
                    - 'enable'
            ft_r0_key_lifetime:
                aliases: ['ft-r0-key-lifetime']
                type: int
                description: Lifetime of the PMK-R0 key in FT, 1-65535 minutes.
            gas_comeback_delay:
                aliases: ['gas-comeback-delay']
                type: int
                description: GAS comeback delay
            gas_fragmentation_limit:
                aliases: ['gas-fragmentation-limit']
                type: int
                description: GAS fragmentation limit
            gtk_rekey:
                aliases: ['gtk-rekey']
                type: str
                description: Enable/disable GTK rekey for WPA security.
                choices:
                    - 'disable'
                    - 'enable'
            gtk_rekey_intv:
                aliases: ['gtk-rekey-intv']
                type: int
                description: GTK rekey interval
            high_efficiency:
                aliases: ['high-efficiency']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            hotspot20_profile:
                aliases: ['hotspot20-profile']
                type: list
                elements: str
                description: Hotspot 2.
            igmp_snooping:
                aliases: ['igmp-snooping']
                type: str
                description: Enable/disable IGMP snooping.
                choices:
                    - 'disable'
                    - 'enable'
            intra_vap_privacy:
                aliases: ['intra-vap-privacy']
                type: str
                description: Enable/disable blocking communication between clients on the same SSID
                choices:
                    - 'disable'
                    - 'enable'
            ip:
                type: list
                elements: str
                description: IP address and subnet mask for the local standalone NAT subnet.
            ips_sensor:
                aliases: ['ips-sensor']
                type: list
                elements: str
                description: IPS sensor name.
            ipv6_rules:
                aliases: ['ipv6-rules']
                type: list
                elements: str
                description: Optional rules of IPv6 packets.
                choices:
                    - 'drop-icmp6ra'
                    - 'drop-icmp6rs'
                    - 'drop-llmnr6'
                    - 'drop-icmp6mld2'
                    - 'drop-dhcp6s'
                    - 'drop-dhcp6c'
                    - 'ndp-proxy'
                    - 'drop-ns-dad'
                    - 'drop-ns-nondad'
            key:
                type: list
                elements: str
                description: WEP Key.
            keyindex:
                type: int
                description: WEP key index
            l3_roaming:
                aliases: ['l3-roaming']
                type: str
                description: Enable/disable layer 3 roaming
                choices:
                    - 'disable'
                    - 'enable'
            l3_roaming_mode:
                aliases: ['l3-roaming-mode']
                type: str
                description: Select the way that layer 3 roaming traffic is passed
                choices:
                    - 'direct'
                    - 'indirect'
            ldpc:
                type: str
                description: VAP low-density parity-check
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'rxtx'
            local_authentication:
                aliases: ['local-authentication']
                type: str
                description: Enable/disable AP local authentication.
                choices:
                    - 'disable'
                    - 'enable'
            local_bridging:
                aliases: ['local-bridging']
                type: str
                description: Enable/disable bridging of wireless and Ethernet interfaces on the FortiAP
                choices:
                    - 'disable'
                    - 'enable'
            local_lan:
                aliases: ['local-lan']
                type: str
                description: Allow/deny traffic destined for a Class A, B, or C private IP address
                choices:
                    - 'deny'
                    - 'allow'
            local_standalone:
                aliases: ['local-standalone']
                type: str
                description: Enable/disable AP local standalone
                choices:
                    - 'disable'
                    - 'enable'
            local_standalone_dns:
                aliases: ['local-standalone-dns']
                type: str
                description: Enable/disable AP local standalone DNS.
                choices:
                    - 'disable'
                    - 'enable'
            local_standalone_dns_ip:
                aliases: ['local-standalone-dns-ip']
                type: list
                elements: str
                description: IPv4 addresses for the local standalone DNS.
            local_standalone_nat:
                aliases: ['local-standalone-nat']
                type: str
                description: Enable/disable AP local standalone NAT mode.
                choices:
                    - 'disable'
                    - 'enable'
            mac_auth_bypass:
                aliases: ['mac-auth-bypass']
                type: str
                description: Enable/disable MAC authentication bypass.
                choices:
                    - 'disable'
                    - 'enable'
            mac_called_station_delimiter:
                aliases: ['mac-called-station-delimiter']
                type: str
                description: MAC called station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_calling_station_delimiter:
                aliases: ['mac-calling-station-delimiter']
                type: str
                description: MAC calling station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_case:
                aliases: ['mac-case']
                type: str
                description: MAC case
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac_password_delimiter:
                aliases: ['mac-password-delimiter']
                type: str
                description: MAC authentication password delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_username_delimiter:
                aliases: ['mac-username-delimiter']
                type: str
                description: MAC authentication username delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Maximum number of clients that can connect simultaneously to the VAP
            max_clients_ap:
                aliases: ['max-clients-ap']
                type: int
                description: Maximum number of clients that can connect simultaneously to the VAP per AP radio
            mbo:
                type: str
                description: Enable/disable Multiband Operation
                choices:
                    - 'disable'
                    - 'enable'
            mbo_cell_data_conn_pref:
                aliases: ['mbo-cell-data-conn-pref']
                type: str
                description: MBO cell data connection preference
                choices:
                    - 'excluded'
                    - 'prefer-not'
                    - 'prefer-use'
            me_disable_thresh:
                aliases: ['me-disable-thresh']
                type: int
                description: Disable multicast enhancement when this many clients are receiving multicast traffic.
            mesh_backhaul:
                aliases: ['mesh-backhaul']
                type: str
                description: Enable/disable using this VAP as a WiFi mesh backhaul
                choices:
                    - 'disable'
                    - 'enable'
            mpsk_profile:
                aliases: ['mpsk-profile']
                type: list
                elements: str
                description: MPSK profile name.
            mu_mimo:
                aliases: ['mu-mimo']
                type: str
                description: Enable/disable Multi-user MIMO
                choices:
                    - 'disable'
                    - 'enable'
            multicast_enhance:
                aliases: ['multicast-enhance']
                type: str
                description: Enable/disable converting multicast to unicast to improve performance
                choices:
                    - 'disable'
                    - 'enable'
            multicast_rate:
                aliases: ['multicast-rate']
                type: str
                description: Multicast rate
                choices:
                    - '0'
                    - '6000'
                    - '12000'
                    - '24000'
            nac:
                type: str
                description: Enable/disable network access control.
                choices:
                    - 'disable'
                    - 'enable'
            nac_profile:
                aliases: ['nac-profile']
                type: list
                elements: str
                description: NAC profile name.
            name:
                type: str
                description: Virtual AP name.
                required: true
            nas_filter_rule:
                aliases: ['nas-filter-rule']
                type: str
                description: Enable/disable NAS filter rule support
                choices:
                    - 'disable'
                    - 'enable'
            neighbor_report_dual_band:
                aliases: ['neighbor-report-dual-band']
                type: str
                description: Enable/disable dual-band neighbor report
                choices:
                    - 'disable'
                    - 'enable'
            okc:
                type: str
                description: Enable/disable Opportunistic Key Caching
                choices:
                    - 'disable'
                    - 'enable'
            osen:
                type: str
                description: Enable/disable OSEN as part of key management
                choices:
                    - 'disable'
                    - 'enable'
            owe_groups:
                aliases: ['owe-groups']
                type: list
                elements: str
                description: OWE-Groups.
                choices:
                    - '19'
                    - '20'
                    - '21'
            owe_transition:
                aliases: ['owe-transition']
                type: str
                description: Enable/disable OWE transition mode support.
                choices:
                    - 'disable'
                    - 'enable'
            owe_transition_ssid:
                aliases: ['owe-transition-ssid']
                type: str
                description: OWE transition mode peer SSID.
            passphrase:
                type: list
                elements: str
                description: WPA pre-shared key
            pmf:
                type: str
                description: Protected Management Frames
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            pmf_assoc_comeback_timeout:
                aliases: ['pmf-assoc-comeback-timeout']
                type: int
                description: Protected Management Frames
            pmf_sa_query_retry_timeout:
                aliases: ['pmf-sa-query-retry-timeout']
                type: int
                description: Protected Management Frames
            port_macauth:
                aliases: ['port-macauth']
                type: str
                description: Enable/disable LAN port MAC authentication
                choices:
                    - 'disable'
                    - 'radius'
                    - 'address-group'
            port_macauth_reauth_timeout:
                aliases: ['port-macauth-reauth-timeout']
                type: int
                description: LAN port MAC authentication re-authentication timeout value
            port_macauth_timeout:
                aliases: ['port-macauth-timeout']
                type: int
                description: LAN port MAC authentication idle timeout value
            portal_message_override_group:
                aliases: ['portal-message-override-group']
                type: list
                elements: str
                description: Replacement message group for this VAP
            portal_message_overrides:
                aliases: ['portal-message-overrides']
                type: dict
                description: Portal message overrides.
                suboptions:
                    auth_disclaimer_page:
                        aliases: ['auth-disclaimer-page']
                        type: str
                        description: Override auth-disclaimer-page message with message from portal-message-overrides group.
                    auth_login_failed_page:
                        aliases: ['auth-login-failed-page']
                        type: str
                        description: Override auth-login-failed-page message with message from portal-message-overrides group.
                    auth_login_page:
                        aliases: ['auth-login-page']
                        type: str
                        description: Override auth-login-page message with message from portal-message-overrides group.
                    auth_reject_page:
                        aliases: ['auth-reject-page']
                        type: str
                        description: Override auth-reject-page message with message from portal-message-overrides group.
            portal_type:
                aliases: ['portal-type']
                type: str
                description: Captive portal functionality.
                choices:
                    - 'auth'
                    - 'auth+disclaimer'
                    - 'disclaimer'
                    - 'email-collect'
                    - 'cmcc'
                    - 'cmcc-macauth'
                    - 'auth-mac'
                    - 'external-auth'
                    - 'external-macauth'
            primary_wag_profile:
                aliases: ['primary-wag-profile']
                type: list
                elements: str
                description: Primary wireless access gateway profile name.
            probe_resp_suppression:
                aliases: ['probe-resp-suppression']
                type: str
                description: Enable/disable probe response suppression
                choices:
                    - 'disable'
                    - 'enable'
            probe_resp_threshold:
                aliases: ['probe-resp-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP response to probe requests
            ptk_rekey:
                aliases: ['ptk-rekey']
                type: str
                description: Enable/disable PTK rekey for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            ptk_rekey_intv:
                aliases: ['ptk-rekey-intv']
                type: int
                description: PTK rekey interval
            qos_profile:
                aliases: ['qos-profile']
                type: list
                elements: str
                description: Quality of service profile name.
            quarantine:
                type: str
                description: Enable/disable station quarantine
                choices:
                    - 'disable'
                    - 'enable'
            radio_2g_threshold:
                aliases: ['radio-2g-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP response to receive a packet in 2.
            radio_5g_threshold:
                aliases: ['radio-5g-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP response to receive a packet in 5G band
            radio_sensitivity:
                aliases: ['radio-sensitivity']
                type: str
                description: Enable/disable software radio sensitivity
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_auth:
                aliases: ['radius-mac-auth']
                type: str
                description: Enable/disable RADIUS-based MAC authentication of clients
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_auth_block_interval:
                aliases: ['radius-mac-auth-block-interval']
                type: int
                description: Dont send RADIUS MAC auth request again if the client has been rejected within specific interval
            radius_mac_auth_server:
                aliases: ['radius-mac-auth-server']
                type: list
                elements: str
                description: RADIUS-based MAC authentication server.
            radius_mac_auth_usergroups:
                aliases: ['radius-mac-auth-usergroups']
                type: list
                elements: str
                description: Selective user groups that are permitted for RADIUS mac authentication.
            radius_mac_mpsk_auth:
                aliases: ['radius-mac-mpsk-auth']
                type: str
                description: Enable/disable RADIUS-based MAC authentication of clients for MPSK authentication
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_mpsk_timeout:
                aliases: ['radius-mac-mpsk-timeout']
                type: int
                description: RADIUS MAC MPSK cache timeout interval
            radius_server:
                aliases: ['radius-server']
                type: list
                elements: str
                description: RADIUS server to be used to authenticate WiFi users.
            rates_11a:
                aliases: ['rates-11a']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates_11ac_mcs_map:
                aliases: ['rates-11ac-mcs-map']
                type: str
                description: Comma separated list of max supported VHT MCS for spatial streams 1 through 8.
            rates_11ax_mcs_map:
                aliases: ['rates-11ax-mcs-map']
                type: str
                description: Comma separated list of max supported HE MCS for spatial streams 1 through 8.
            rates_11be_mcs_map:
                aliases: ['rates-11be-mcs-map']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 20MHz/40MHz/80MHz bandwidth.
            rates_11be_mcs_map_160:
                aliases: ['rates-11be-mcs-map-160']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 160MHz bandwidth.
            rates_11be_mcs_map_320:
                aliases: ['rates-11be-mcs-map-320']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 320MHz bandwidth.
            rates_11bg:
                aliases: ['rates-11bg']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates_11n_ss12:
                aliases: ['rates-11n-ss12']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
                    - 'mcs12/2'
                    - 'mcs13/2'
                    - 'mcs14/2'
                    - 'mcs15/2'
            rates_11n_ss34:
                aliases: ['rates-11n-ss34']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs16/3'
                    - 'mcs17/3'
                    - 'mcs18/3'
                    - 'mcs19/3'
                    - 'mcs20/3'
                    - 'mcs21/3'
                    - 'mcs22/3'
                    - 'mcs23/3'
                    - 'mcs24/4'
                    - 'mcs25/4'
                    - 'mcs26/4'
                    - 'mcs27/4'
                    - 'mcs28/4'
                    - 'mcs29/4'
                    - 'mcs30/4'
                    - 'mcs31/4'
            roaming_acct_interim_update:
                aliases: ['roaming-acct-interim-update']
                type: str
                description: Enable/disable using accounting interim update instead of accounting start/stop on roaming for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            sae_groups:
                aliases: ['sae-groups']
                type: list
                elements: str
                description: SAE-Groups.
                choices:
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
            sae_h2e_only:
                aliases: ['sae-h2e-only']
                type: str
                description: Use hash-to-element-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
            sae_hnp_only:
                aliases: ['sae-hnp-only']
                type: str
                description: Use hunting-and-pecking-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
            sae_password:
                aliases: ['sae-password']
                type: list
                elements: str
                description: WPA3 SAE password to be used to authenticate WiFi users.
            sae_pk:
                aliases: ['sae-pk']
                type: str
                description: Enable/disable WPA3 SAE-PK
                choices:
                    - 'disable'
                    - 'enable'
            sae_private_key:
                aliases: ['sae-private-key']
                type: str
                description: Private key used for WPA3 SAE-PK authentication.
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Block or monitor connections to Botnet servers or disable Botnet scanning.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: list
                elements: str
                description: Firewall schedules for enabling this VAP on the FortiAP.
            secondary_wag_profile:
                aliases: ['secondary-wag-profile']
                type: list
                elements: str
                description: Secondary wireless access gateway profile name.
            security:
                type: str
                description: Security mode for the wireless interface
                choices:
                    - 'None'
                    - 'wep64'
                    - 'wep128'
                    - 'WPA_PSK'
                    - 'WPA_RADIUS'
                    - 'WPA'
                    - 'WPA2'
                    - 'WPA2_AUTO'
                    - 'open'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
                    - 'captive-portal'
                    - 'wpa-only-personal'
                    - 'wpa-only-enterprise'
                    - 'wpa2-only-personal'
                    - 'wpa2-only-enterprise'
                    - 'wpa-personal+captive-portal'
                    - 'wpa-only-personal+captive-portal'
                    - 'wpa2-only-personal+captive-portal'
                    - 'osen'
                    - 'wpa3-enterprise'
                    - 'sae'
                    - 'sae-transition'
                    - 'owe'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
                    - 'wpa3-only-enterprise'
                    - 'wpa3-enterprise-transition'
            security_exempt_list:
                aliases: ['security-exempt-list']
                type: list
                elements: str
                description: Optional security exempt list for captive portal authentication.
            security_obsolete_option:
                aliases: ['security-obsolete-option']
                type: str
                description: Enable/disable obsolete security options.
                choices:
                    - 'disable'
                    - 'enable'
            security_redirect_url:
                aliases: ['security-redirect-url']
                type: str
                description: Optional URL for redirecting users after they pass captive portal authentication.
            selected_usergroups:
                aliases: ['selected-usergroups']
                type: list
                elements: str
                description: Selective user groups that are permitted to authenticate.
            split_tunneling:
                aliases: ['split-tunneling']
                type: str
                description: Enable/disable split tunneling
                choices:
                    - 'disable'
                    - 'enable'
            ssid:
                type: str
                description: IEEE 802.
            sticky_client_remove:
                aliases: ['sticky-client-remove']
                type: str
                description: Enable/disable sticky client remove to maintain good signal level clients in SSID
                choices:
                    - 'disable'
                    - 'enable'
            sticky_client_threshold_2g:
                aliases: ['sticky-client-threshold-2g']
                type: str
                description: Minimum signal level/threshold in dBm required for the 2G client to be serviced by the AP
            sticky_client_threshold_5g:
                aliases: ['sticky-client-threshold-5g']
                type: str
                description: Minimum signal level/threshold in dBm required for the 5G client to be serviced by the AP
            sticky_client_threshold_6g:
                aliases: ['sticky-client-threshold-6g']
                type: str
                description: Minimum signal level/threshold in dBm required for the 6G client to be serviced by the AP
            target_wake_time:
                aliases: ['target-wake-time']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            tkip_counter_measure:
                aliases: ['tkip-counter-measure']
                type: str
                description: Enable/disable TKIP counter measure.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_echo_interval:
                aliases: ['tunnel-echo-interval']
                type: int
                description: The time interval to send echo to both primary and secondary tunnel peers
            tunnel_fallback_interval:
                aliases: ['tunnel-fallback-interval']
                type: int
                description: The time interval for secondary tunnel to fall back to primary tunnel
            usergroup:
                type: list
                elements: str
                description: Firewall user group to be used to authenticate WiFi users.
            utm_log:
                aliases: ['utm-log']
                type: str
                description: Enable/disable UTM logging.
                choices:
                    - 'disable'
                    - 'enable'
            utm_profile:
                aliases: ['utm-profile']
                type: list
                elements: str
                description: UTM profile name.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable to add one or more security profiles
                choices:
                    - 'disable'
                    - 'enable'
            vlan_auto:
                aliases: ['vlan-auto']
                type: str
                description: Enable/disable automatic management of SSID VLAN interface.
                choices:
                    - 'disable'
                    - 'enable'
            vlan_name:
                aliases: ['vlan-name']
                type: list
                elements: dict
                description: Vlan name.
                suboptions:
                    name:
                        type: str
                        description: VLAN name.
                    vlan_id:
                        aliases: ['vlan-id']
                        type: int
                        description: VLAN IDs
            vlan_pool:
                aliases: ['vlan-pool']
                type: list
                elements: dict
                description: Vlan pool.
                suboptions:
                    _wtp_group:
                        aliases: ['_wtp-group']
                        type: str
                        description: Wtp group.
                    id:
                        type: int
                        description: ID.
                    wtp_group:
                        aliases: ['wtp-group']
                        type: list
                        elements: str
                        description: WTP group name.
            vlan_pooling:
                aliases: ['vlan-pooling']
                type: str
                description: Enable/disable VLAN pooling, to allow grouping of multiple wireless controller VLANs into VLAN pools
                choices:
                    - 'wtp-group'
                    - 'round-robin'
                    - 'hash'
                    - 'disable'
            vlanid:
                type: int
                description: Optional VLAN ID.
            voice_enterprise:
                aliases: ['voice-enterprise']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: list
                elements: str
                description: WebFilter profile name.
            mac_filter_policy_other:
                aliases: ['mac-filter-policy-other']
                type: str
                description: Allow or block clients with MAC addresses that are not in the filter list.
                choices:
                    - 'deny'
                    - 'allow'
            mac_filter:
                aliases: ['mac-filter']
                type: str
                description: Enable/disable MAC filtering to block wireless clients by mac address.
                choices:
                    - 'disable'
                    - 'enable'
            rates_11ax_ss12:
                aliases: ['rates-11ax-ss12']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates_11ac_ss34:
                aliases: ['rates-11ac-ss34']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates_11ax_ss34:
                aliases: ['rates-11ax-ss34']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates_11ac_ss12:
                aliases: ['rates-11ac-ss12']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs10/2'
                    - 'mcs11/2'
            mac_filter_list:
                aliases: ['mac-filter-list']
                type: list
                elements: dict
                description: Mac filter list.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    mac:
                        type: str
                        description: MAC address.
                    mac_filter_policy:
                        aliases: ['mac-filter-policy']
                        type: str
                        description: Deny or allow the client with this MAC address.
                        choices:
                            - 'deny'
                            - 'allow'
            mpsk_key:
                aliases: ['mpsk-key']
                type: list
                elements: dict
                description: Mpsk key.
                suboptions:
                    comment:
                        type: str
                        description: Comment.
                    concurrent_clients:
                        aliases: ['concurrent-clients']
                        type: str
                        description: Number of clients that can connect using this pre-shared key.
                    key_name:
                        aliases: ['key-name']
                        type: str
                        description: Pre-shared key name.
                    mpsk_schedules:
                        aliases: ['mpsk-schedules']
                        type: list
                        elements: str
                        description: Firewall schedule for MPSK passphrase.
                    passphrase:
                        type: list
                        elements: str
                        description: WPA Pre-shared key.
            mpsk:
                type: str
                description: Enable/disable multiple PSK authentication.
                choices:
                    - 'disable'
                    - 'enable'
            mpsk_concurrent_clients:
                aliases: ['mpsk-concurrent-clients']
                type: int
                description: Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication
            acct_interim_interval:
                aliases: ['acct-interim-interval']
                type: int
                description: WiFi RADIUS accounting interim interval
            captive_portal_radius_server:
                aliases: ['captive-portal-radius-server']
                type: str
                description: Captive portal RADIUS server domain name or IP address.
            captive_portal_session_timeout_interval:
                aliases: ['captive-portal-session-timeout-interval']
                type: int
                description: Session timeout interval
            captive_portal_radius_secret:
                aliases: ['captive-portal-radius-secret']
                type: list
                elements: str
                description: Secret key to access the RADIUS server.
            captive_portal_macauth_radius_secret:
                aliases: ['captive-portal-macauth-radius-secret']
                type: list
                elements: str
                description: Secret key to access the macauth RADIUS server.
            captive_portal_macauth_radius_server:
                aliases: ['captive-portal-macauth-radius-server']
                type: str
                description: Captive portal external RADIUS server domain name or IP address.
            _intf_ip_managed_by_fortiipam:
                aliases: ['_intf_ip-managed-by-fortiipam']
                type: str
                description: Intf ip managed by fortiipam.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'inherit-global'
            _intf_managed_subnetwork_size:
                aliases: ['_intf_managed-subnetwork-size']
                type: str
                description: Intf managed subnetwork size.
                choices:
                    - '32'
                    - '64'
                    - '128'
                    - '256'
                    - '512'
                    - '1024'
                    - '2048'
                    - '4096'
                    - '8192'
                    - '16384'
                    - '32768'
                    - '65536'
            domain_name_stripping:
                aliases: ['domain-name-stripping']
                type: str
                description: Enable/disable stripping domain name from identity
                choices:
                    - 'disable'
                    - 'enable'
            local_lan_partition:
                aliases: ['local-lan-partition']
                type: str
                description: Enable/disable segregating client traffic to local LAN side
                choices:
                    - 'disable'
                    - 'enable'
            _intf_role:
                type: str
                description: Intf role.
                choices:
                    - 'lan'
                    - 'wan'
                    - 'dmz'
                    - 'undefined'
            called_station_id_type:
                aliases: ['called-station-id-type']
                type: str
                description: The format type of RADIUS attribute Called-Station-Id
                choices:
                    - 'mac'
                    - 'ip'
                    - 'apname'
            external_pre_auth:
                aliases: ['external-pre-auth']
                type: str
                description: Enable/disable pre-authentication with external APs not managed by the FortiGate
                choices:
                    - 'disable'
                    - 'enable'
            pre_auth:
                aliases: ['pre-auth']
                type: str
                description: Enable/disable pre-authentication, where supported by clients
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
    - name: Configure Virtual Access Points
      fortinet.fmgdevice.fmgd_wireless_vap:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_vap:
          name: "your value" # Required variable, string
          # d80211k: <value in [disable, enable]>
          # d80211v: <value in [disable, enable]>
          # _centmgmt: <value in [disable, enable]>
          # _dhcp_svr_id: <list or string>
          # _intf_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "fgfm"
          #   - "radius-acct"
          #   - "probe-response"
          #   - "capwap"
          #   - "dnp"
          #   - "ftm"
          #   - "fabric"
          #   - "speed-test"
          # _intf_device_access_list: <list or string>
          # _intf_device_identification: <value in [disable, enable]>
          # _intf_device_netscan: <value in [disable, enable]>
          # _intf_dhcp_relay_ip: <list or string>
          # _intf_dhcp_relay_service: <value in [disable, enable]>
          # _intf_dhcp_relay_type: <value in [regular, ipsec]>
          # _intf_dhcp6_relay_ip: <list or string>
          # _intf_dhcp6_relay_service: <value in [disable, enable]>
          # _intf_dhcp6_relay_type: <value in [regular]>
          # _intf_ip: <list or string>
          # _intf_ip6_address: <string>
          # _intf_ip6_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "any"
          #   - "fgfm"
          #   - "capwap"
          # _intf_listen_forticlient_connection: <value in [disable, enable]>
          # _is_factory_setting: <value in [disable, enable, ext]>
          # access_control_list: <list or string>
          # additional_akms:
          #   - "akm6"
          #   - "akm24"
          # address_group: <list or string>
          # address_group_policy: <value in [disable, allow, deny]>
          # akm24_only: <value in [disable, enable]>
          # alias: <string>
          # antivirus_profile: <list or string>
          # application_detection_engine: <value in [disable, enable]>
          # application_dscp_marking: <value in [disable, enable]>
          # application_list: <list or string>
          # application_report_intv: <integer>
          # atf_weight: <integer>
          # auth: <value in [radius, usergroup, psk]>
          # auth_cert: <list or string>
          # auth_portal_addr: <string>
          # beacon_advertising:
          #   - "name"
          #   - "model"
          #   - "serial-number"
          # beacon_protection: <value in [disable, enable]>
          # broadcast_ssid: <value in [disable, enable]>
          # broadcast_suppression:
          #   - "dhcp"
          #   - "arp"
          #   - "dhcp2"
          #   - "arp2"
          #   - "netbios-ns"
          #   - "netbios-ds"
          #   - "arp3"
          #   - "dhcp-up"
          #   - "dhcp-down"
          #   - "arp-known"
          #   - "arp-unknown"
          #   - "arp-reply"
          #   - "ipv6"
          #   - "dhcp-starvation"
          #   - "arp-poison"
          #   - "all-other-mc"
          #   - "all-other-bc"
          #   - "arp-proxy"
          #   - "dhcp-ucast"
          # bss_color_partial: <value in [disable, enable]>
          # bstm_disassociation_imminent: <value in [disable, enable]>
          # bstm_load_balancing_disassoc_timer: <integer>
          # bstm_rssi_disassoc_timer: <integer>
          # captive_portal: <value in [disable, enable]>
          # captive_portal_ac_name: <string>
          # captive_portal_auth_timeout: <integer>
          # captive_portal_fw_accounting: <value in [disable, enable]>
          # dhcp_address_enforcement: <value in [disable, enable]>
          # dhcp_lease_time: <integer>
          # dhcp_option43_insertion: <value in [disable, enable]>
          # dhcp_option82_circuit_id_insertion: <value in [disable, style-1, style-2, ...]>
          # dhcp_option82_insertion: <value in [disable, enable]>
          # dhcp_option82_remote_id_insertion: <value in [disable, style-1]>
          # dynamic_vlan: <value in [disable, enable]>
          # dynamic_mapping:
          #   - d80211k: <value in [disable, enable]>
          #     d80211v: <value in [disable, enable]>
          #     _centmgmt: <value in [disable, enable]>
          #     _dhcp_svr_id: <list or string>
          #     _intf_allowaccess:
          #       - "https"
          #       - "ping"
          #       - "ssh"
          #       - "snmp"
          #       - "http"
          #       - "telnet"
          #       - "fgfm"
          #       - "radius-acct"
          #       - "probe-response"
          #       - "capwap"
          #       - "dnp"
          #       - "ftm"
          #       - "fabric"
          #       - "speed-test"
          #     _intf_device_access_list: <list or string>
          #     _intf_device_identification: <value in [disable, enable]>
          #     _intf_device_netscan: <value in [disable, enable]>
          #     _intf_dhcp_relay_ip: <list or string>
          #     _intf_dhcp_relay_service: <value in [disable, enable]>
          #     _intf_dhcp_relay_type: <value in [regular, ipsec]>
          #     _intf_dhcp6_relay_ip: <list or string>
          #     _intf_dhcp6_relay_service: <value in [disable, enable]>
          #     _intf_dhcp6_relay_type: <value in [regular]>
          #     _intf_ip: <list or string>
          #     _intf_ip6_address: <string>
          #     _intf_ip6_allowaccess:
          #       - "https"
          #       - "ping"
          #       - "ssh"
          #       - "snmp"
          #       - "http"
          #       - "telnet"
          #       - "any"
          #       - "fgfm"
          #       - "capwap"
          #     _intf_listen_forticlient_connection: <value in [disable, enable]>
          #     _is_factory_setting: <value in [disable, enable, ext]>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     access_control_list: <list or string>
          #     acct_interim_interval: <integer>
          #     additional_akms:
          #       - "akm6"
          #       - "akm24"
          #     address_group: <list or string>
          #     address_group_policy: <value in [disable, allow, deny]>
          #     akm24_only: <value in [disable, enable]>
          #     alias: <string>
          #     antivirus_profile: <list or string>
          #     application_detection_engine: <value in [disable, enable]>
          #     application_dscp_marking: <value in [disable, enable]>
          #     application_list: <list or string>
          #     application_report_intv: <integer>
          #     atf_weight: <integer>
          #     auth: <value in [radius, usergroup, psk]>
          #     auth_cert: <list or string>
          #     auth_portal_addr: <string>
          #     beacon_advertising:
          #       - "name"
          #       - "model"
          #       - "serial-number"
          #     beacon_protection: <value in [disable, enable]>
          #     broadcast_ssid: <value in [disable, enable]>
          #     broadcast_suppression:
          #       - "dhcp"
          #       - "arp"
          #       - "dhcp2"
          #       - "arp2"
          #       - "netbios-ns"
          #       - "netbios-ds"
          #       - "arp3"
          #       - "dhcp-up"
          #       - "dhcp-down"
          #       - "arp-known"
          #       - "arp-unknown"
          #       - "arp-reply"
          #       - "ipv6"
          #       - "dhcp-starvation"
          #       - "arp-poison"
          #       - "all-other-mc"
          #       - "all-other-bc"
          #       - "arp-proxy"
          #       - "dhcp-ucast"
          #     bss_color_partial: <value in [disable, enable]>
          #     bstm_disassociation_imminent: <value in [disable, enable]>
          #     bstm_load_balancing_disassoc_timer: <integer>
          #     bstm_rssi_disassoc_timer: <integer>
          #     captive_portal: <value in [disable, enable]>
          #     captive_portal_ac_name: <string>
          #     captive_portal_auth_timeout: <integer>
          #     captive_portal_fw_accounting: <value in [disable, enable]>
          #     captive_portal_macauth_radius_secret: <list or string>
          #     captive_portal_macauth_radius_server: <string>
          #     captive_portal_radius_secret: <list or string>
          #     captive_portal_radius_server: <string>
          #     captive_portal_session_timeout_interval: <integer>
          #     client_count: <integer>
          #     dhcp_address_enforcement: <value in [disable, enable]>
          #     dhcp_lease_time: <integer>
          #     dhcp_option43_insertion: <value in [disable, enable]>
          #     dhcp_option82_circuit_id_insertion: <value in [disable, style-1, style-2, ...]>
          #     dhcp_option82_insertion: <value in [disable, enable]>
          #     dhcp_option82_remote_id_insertion: <value in [disable, style-1]>
          #     dynamic_vlan: <value in [disable, enable]>
          #     eap_reauth: <value in [disable, enable]>
          #     eap_reauth_intv: <integer>
          #     eapol_key_retries: <value in [disable, enable]>
          #     encrypt: <value in [TKIP, AES, TKIP-AES]>
          #     external_fast_roaming: <value in [disable, enable]>
          #     external_logout: <string>
          #     external_web: <string>
          #     external_web_format: <value in [auto-detect, no-query-string, partial-query-string]>
          #     fast_bss_transition: <value in [disable, enable]>
          #     fast_roaming: <value in [disable, enable]>
          #     ft_mobility_domain: <integer>
          #     ft_over_ds: <value in [disable, enable]>
          #     ft_r0_key_lifetime: <integer>
          #     gas_comeback_delay: <integer>
          #     gas_fragmentation_limit: <integer>
          #     gtk_rekey: <value in [disable, enable]>
          #     gtk_rekey_intv: <integer>
          #     high_efficiency: <value in [disable, enable]>
          #     hotspot20_profile: <list or string>
          #     igmp_snooping: <value in [disable, enable]>
          #     intra_vap_privacy: <value in [disable, enable]>
          #     ip: <list or string>
          #     ips_sensor: <list or string>
          #     ipv6_rules:
          #       - "drop-icmp6ra"
          #       - "drop-icmp6rs"
          #       - "drop-llmnr6"
          #       - "drop-icmp6mld2"
          #       - "drop-dhcp6s"
          #       - "drop-dhcp6c"
          #       - "ndp-proxy"
          #       - "drop-ns-dad"
          #       - "drop-ns-nondad"
          #     key: <list or string>
          #     keyindex: <integer>
          #     l3_roaming: <value in [disable, enable]>
          #     l3_roaming_mode: <value in [direct, indirect]>
          #     ldpc: <value in [disable, tx, rx, ...]>
          #     local_authentication: <value in [disable, enable]>
          #     local_bridging: <value in [disable, enable]>
          #     local_lan: <value in [deny, allow]>
          #     local_standalone: <value in [disable, enable]>
          #     local_standalone_dns: <value in [disable, enable]>
          #     local_standalone_dns_ip: <list or string>
          #     local_standalone_nat: <value in [disable, enable]>
          #     local_switching: <value in [disable, enable]>
          #     mac_auth_bypass: <value in [disable, enable]>
          #     mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     mac_case: <value in [uppercase, lowercase]>
          #     mac_filter: <value in [disable, enable]>
          #     mac_filter_policy_other: <value in [deny, allow]>
          #     mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     max_clients: <integer>
          #     max_clients_ap: <integer>
          #     mbo: <value in [disable, enable]>
          #     mbo_cell_data_conn_pref: <value in [excluded, prefer-not, prefer-use]>
          #     me_disable_thresh: <integer>
          #     mesh_backhaul: <value in [disable, enable]>
          #     mpsk: <value in [disable, enable]>
          #     mpsk_concurrent_clients: <integer>
          #     mpsk_profile: <list or string>
          #     mu_mimo: <value in [disable, enable]>
          #     multicast_enhance: <value in [disable, enable]>
          #     multicast_rate: <value in [0, 6000, 12000, ...]>
          #     nac: <value in [disable, enable]>
          #     nac_profile: <list or string>
          #     nas_filter_rule: <value in [disable, enable]>
          #     neighbor_report_dual_band: <value in [disable, enable]>
          #     okc: <value in [disable, enable]>
          #     osen: <value in [disable, enable]>
          #     owe_groups:
          #       - "19"
          #       - "20"
          #       - "21"
          #     owe_transition: <value in [disable, enable]>
          #     owe_transition_ssid: <string>
          #     passphrase: <list or string>
          #     pmf: <value in [disable, enable, optional]>
          #     pmf_assoc_comeback_timeout: <integer>
          #     pmf_sa_query_retry_timeout: <integer>
          #     port_macauth: <value in [disable, radius, address-group]>
          #     port_macauth_reauth_timeout: <integer>
          #     port_macauth_timeout: <integer>
          #     portal_message_override_group: <list or string>
          #     portal_type: <value in [auth, auth+disclaimer, disclaimer, ...]>
          #     primary_wag_profile: <list or string>
          #     probe_resp_suppression: <value in [disable, enable]>
          #     probe_resp_threshold: <string>
          #     ptk_rekey: <value in [disable, enable]>
          #     ptk_rekey_intv: <integer>
          #     qos_profile: <list or string>
          #     quarantine: <value in [disable, enable]>
          #     radio_2g_threshold: <string>
          #     radio_5g_threshold: <string>
          #     radio_sensitivity: <value in [disable, enable]>
          #     radius_mac_auth: <value in [disable, enable]>
          #     radius_mac_auth_block_interval: <integer>
          #     radius_mac_auth_server: <list or string>
          #     radius_mac_auth_usergroups: <list or string>
          #     radius_mac_mpsk_auth: <value in [disable, enable]>
          #     radius_mac_mpsk_timeout: <integer>
          #     radius_server: <list or string>
          #     rates_11a:
          #       - "1"
          #       - "1-basic"
          #       - "2"
          #       - "2-basic"
          #       - "5.5"
          #       - "5.5-basic"
          #       - "6"
          #       - "6-basic"
          #       - "9"
          #       - "9-basic"
          #       - "12"
          #       - "12-basic"
          #       - "18"
          #       - "18-basic"
          #       - "24"
          #       - "24-basic"
          #       - "36"
          #       - "36-basic"
          #       - "48"
          #       - "48-basic"
          #       - "54"
          #       - "54-basic"
          #       - "11"
          #       - "11-basic"
          #     rates_11ac_mcs_map: <string>
          #     rates_11ac_ss12:
          #       - "mcs0/1"
          #       - "mcs1/1"
          #       - "mcs2/1"
          #       - "mcs3/1"
          #       - "mcs4/1"
          #       - "mcs5/1"
          #       - "mcs6/1"
          #       - "mcs7/1"
          #       - "mcs8/1"
          #       - "mcs9/1"
          #       - "mcs0/2"
          #       - "mcs1/2"
          #       - "mcs2/2"
          #       - "mcs3/2"
          #       - "mcs4/2"
          #       - "mcs5/2"
          #       - "mcs6/2"
          #       - "mcs7/2"
          #       - "mcs8/2"
          #       - "mcs9/2"
          #       - "mcs10/1"
          #       - "mcs11/1"
          #       - "mcs10/2"
          #       - "mcs11/2"
          #     rates_11ac_ss34:
          #       - "mcs0/3"
          #       - "mcs1/3"
          #       - "mcs2/3"
          #       - "mcs3/3"
          #       - "mcs4/3"
          #       - "mcs5/3"
          #       - "mcs6/3"
          #       - "mcs7/3"
          #       - "mcs8/3"
          #       - "mcs9/3"
          #       - "mcs0/4"
          #       - "mcs1/4"
          #       - "mcs2/4"
          #       - "mcs3/4"
          #       - "mcs4/4"
          #       - "mcs5/4"
          #       - "mcs6/4"
          #       - "mcs7/4"
          #       - "mcs8/4"
          #       - "mcs9/4"
          #       - "mcs10/3"
          #       - "mcs11/3"
          #       - "mcs10/4"
          #       - "mcs11/4"
          #     rates_11ax_mcs_map: <string>
          #     rates_11ax_ss12:
          #       - "mcs0/1"
          #       - "mcs1/1"
          #       - "mcs2/1"
          #       - "mcs3/1"
          #       - "mcs4/1"
          #       - "mcs5/1"
          #       - "mcs6/1"
          #       - "mcs7/1"
          #       - "mcs8/1"
          #       - "mcs9/1"
          #       - "mcs10/1"
          #       - "mcs11/1"
          #       - "mcs0/2"
          #       - "mcs1/2"
          #       - "mcs2/2"
          #       - "mcs3/2"
          #       - "mcs4/2"
          #       - "mcs5/2"
          #       - "mcs6/2"
          #       - "mcs7/2"
          #       - "mcs8/2"
          #       - "mcs9/2"
          #       - "mcs10/2"
          #       - "mcs11/2"
          #     rates_11ax_ss34:
          #       - "mcs0/3"
          #       - "mcs1/3"
          #       - "mcs2/3"
          #       - "mcs3/3"
          #       - "mcs4/3"
          #       - "mcs5/3"
          #       - "mcs6/3"
          #       - "mcs7/3"
          #       - "mcs8/3"
          #       - "mcs9/3"
          #       - "mcs10/3"
          #       - "mcs11/3"
          #       - "mcs0/4"
          #       - "mcs1/4"
          #       - "mcs2/4"
          #       - "mcs3/4"
          #       - "mcs4/4"
          #       - "mcs5/4"
          #       - "mcs6/4"
          #       - "mcs7/4"
          #       - "mcs8/4"
          #       - "mcs9/4"
          #       - "mcs10/4"
          #       - "mcs11/4"
          #     rates_11be_mcs_map: <string>
          #     rates_11be_mcs_map_160: <string>
          #     rates_11be_mcs_map_320: <string>
          #     rates_11bg:
          #       - "1"
          #       - "1-basic"
          #       - "2"
          #       - "2-basic"
          #       - "5.5"
          #       - "5.5-basic"
          #       - "6"
          #       - "6-basic"
          #       - "9"
          #       - "9-basic"
          #       - "12"
          #       - "12-basic"
          #       - "18"
          #       - "18-basic"
          #       - "24"
          #       - "24-basic"
          #       - "36"
          #       - "36-basic"
          #       - "48"
          #       - "48-basic"
          #       - "54"
          #       - "54-basic"
          #       - "11"
          #       - "11-basic"
          #     rates_11n_ss12:
          #       - "mcs0/1"
          #       - "mcs1/1"
          #       - "mcs2/1"
          #       - "mcs3/1"
          #       - "mcs4/1"
          #       - "mcs5/1"
          #       - "mcs6/1"
          #       - "mcs7/1"
          #       - "mcs8/2"
          #       - "mcs9/2"
          #       - "mcs10/2"
          #       - "mcs11/2"
          #       - "mcs12/2"
          #       - "mcs13/2"
          #       - "mcs14/2"
          #       - "mcs15/2"
          #     rates_11n_ss34:
          #       - "mcs16/3"
          #       - "mcs17/3"
          #       - "mcs18/3"
          #       - "mcs19/3"
          #       - "mcs20/3"
          #       - "mcs21/3"
          #       - "mcs22/3"
          #       - "mcs23/3"
          #       - "mcs24/4"
          #       - "mcs25/4"
          #       - "mcs26/4"
          #       - "mcs27/4"
          #       - "mcs28/4"
          #       - "mcs29/4"
          #       - "mcs30/4"
          #       - "mcs31/4"
          #     roaming_acct_interim_update: <value in [disable, enable]>
          #     sae_groups:
          #       - "1"
          #       - "2"
          #       - "5"
          #       - "14"
          #       - "15"
          #       - "16"
          #       - "17"
          #       - "18"
          #       - "19"
          #       - "20"
          #       - "21"
          #       - "27"
          #       - "28"
          #       - "29"
          #       - "30"
          #       - "31"
          #     sae_h2e_only: <value in [disable, enable]>
          #     sae_hnp_only: <value in [disable, enable]>
          #     sae_password: <list or string>
          #     sae_pk: <value in [disable, enable]>
          #     sae_private_key: <string>
          #     scan_botnet_connections: <value in [disable, block, monitor]>
          #     schedule: <list or string>
          #     secondary_wag_profile: <list or string>
          #     security: <value in [None, wep64, wep128, ...]>
          #     security_exempt_list: <list or string>
          #     security_obsolete_option: <value in [disable, enable]>
          #     security_redirect_url: <string>
          #     selected_usergroups: <list or string>
          #     split_tunneling: <value in [disable, enable]>
          #     ssid: <string>
          #     sticky_client_remove: <value in [disable, enable]>
          #     sticky_client_threshold_2g: <string>
          #     sticky_client_threshold_5g: <string>
          #     sticky_client_threshold_6g: <string>
          #     target_wake_time: <value in [disable, enable]>
          #     tkip_counter_measure: <value in [disable, enable]>
          #     tunnel_echo_interval: <integer>
          #     tunnel_fallback_interval: <integer>
          #     usergroup: <list or string>
          #     utm_log: <value in [disable, enable]>
          #     utm_profile: <list or string>
          #     utm_status: <value in [disable, enable]>
          #     vdom: <list or string>
          #     vlan_auto: <value in [disable, enable]>
          #     vlan_pooling: <value in [wtp-group, round-robin, hash, ...]>
          #     vlanid: <integer>
          #     voice_enterprise: <value in [disable, enable]>
          #     webfilter_profile: <list or string>
          #     _intf_ip_managed_by_fortiipam: <value in [disable, enable, inherit-global]>
          #     _intf_managed_subnetwork_size: <value in [32, 64, 128, ...]>
          #     domain_name_stripping: <value in [disable, enable]>
          #     local_lan_partition: <value in [disable, enable]>
          #     _intf_role: <value in [lan, wan, dmz, ...]>
          #     called_station_id_type: <value in [mac, ip, apname]>
          #     external_pre_auth: <value in [disable, enable]>
          #     pre_auth: <value in [disable, enable]>
          # eap_reauth: <value in [disable, enable]>
          # eap_reauth_intv: <integer>
          # eapol_key_retries: <value in [disable, enable]>
          # encrypt: <value in [TKIP, AES, TKIP-AES]>
          # external_fast_roaming: <value in [disable, enable]>
          # external_logout: <string>
          # external_web: <string>
          # external_web_format: <value in [auto-detect, no-query-string, partial-query-string]>
          # fast_bss_transition: <value in [disable, enable]>
          # fast_roaming: <value in [disable, enable]>
          # ft_mobility_domain: <integer>
          # ft_over_ds: <value in [disable, enable]>
          # ft_r0_key_lifetime: <integer>
          # gas_comeback_delay: <integer>
          # gas_fragmentation_limit: <integer>
          # gtk_rekey: <value in [disable, enable]>
          # gtk_rekey_intv: <integer>
          # high_efficiency: <value in [disable, enable]>
          # hotspot20_profile: <list or string>
          # igmp_snooping: <value in [disable, enable]>
          # intra_vap_privacy: <value in [disable, enable]>
          # ip: <list or string>
          # ips_sensor: <list or string>
          # ipv6_rules:
          #   - "drop-icmp6ra"
          #   - "drop-icmp6rs"
          #   - "drop-llmnr6"
          #   - "drop-icmp6mld2"
          #   - "drop-dhcp6s"
          #   - "drop-dhcp6c"
          #   - "ndp-proxy"
          #   - "drop-ns-dad"
          #   - "drop-ns-nondad"
          # key: <list or string>
          # keyindex: <integer>
          # l3_roaming: <value in [disable, enable]>
          # l3_roaming_mode: <value in [direct, indirect]>
          # ldpc: <value in [disable, tx, rx, ...]>
          # local_authentication: <value in [disable, enable]>
          # local_bridging: <value in [disable, enable]>
          # local_lan: <value in [deny, allow]>
          # local_standalone: <value in [disable, enable]>
          # local_standalone_dns: <value in [disable, enable]>
          # local_standalone_dns_ip: <list or string>
          # local_standalone_nat: <value in [disable, enable]>
          # mac_auth_bypass: <value in [disable, enable]>
          # mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_case: <value in [uppercase, lowercase]>
          # mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # max_clients: <integer>
          # max_clients_ap: <integer>
          # mbo: <value in [disable, enable]>
          # mbo_cell_data_conn_pref: <value in [excluded, prefer-not, prefer-use]>
          # me_disable_thresh: <integer>
          # mesh_backhaul: <value in [disable, enable]>
          # mpsk_profile: <list or string>
          # mu_mimo: <value in [disable, enable]>
          # multicast_enhance: <value in [disable, enable]>
          # multicast_rate: <value in [0, 6000, 12000, ...]>
          # nac: <value in [disable, enable]>
          # nac_profile: <list or string>
          # nas_filter_rule: <value in [disable, enable]>
          # neighbor_report_dual_band: <value in [disable, enable]>
          # okc: <value in [disable, enable]>
          # osen: <value in [disable, enable]>
          # owe_groups:
          #   - "19"
          #   - "20"
          #   - "21"
          # owe_transition: <value in [disable, enable]>
          # owe_transition_ssid: <string>
          # passphrase: <list or string>
          # pmf: <value in [disable, enable, optional]>
          # pmf_assoc_comeback_timeout: <integer>
          # pmf_sa_query_retry_timeout: <integer>
          # port_macauth: <value in [disable, radius, address-group]>
          # port_macauth_reauth_timeout: <integer>
          # port_macauth_timeout: <integer>
          # portal_message_override_group: <list or string>
          # portal_message_overrides:
          #   auth_disclaimer_page: <string>
          #   auth_login_failed_page: <string>
          #   auth_login_page: <string>
          #   auth_reject_page: <string>
          # portal_type: <value in [auth, auth+disclaimer, disclaimer, ...]>
          # primary_wag_profile: <list or string>
          # probe_resp_suppression: <value in [disable, enable]>
          # probe_resp_threshold: <string>
          # ptk_rekey: <value in [disable, enable]>
          # ptk_rekey_intv: <integer>
          # qos_profile: <list or string>
          # quarantine: <value in [disable, enable]>
          # radio_2g_threshold: <string>
          # radio_5g_threshold: <string>
          # radio_sensitivity: <value in [disable, enable]>
          # radius_mac_auth: <value in [disable, enable]>
          # radius_mac_auth_block_interval: <integer>
          # radius_mac_auth_server: <list or string>
          # radius_mac_auth_usergroups: <list or string>
          # radius_mac_mpsk_auth: <value in [disable, enable]>
          # radius_mac_mpsk_timeout: <integer>
          # radius_server: <list or string>
          # rates_11a:
          #   - "1"
          #   - "1-basic"
          #   - "2"
          #   - "2-basic"
          #   - "5.5"
          #   - "5.5-basic"
          #   - "6"
          #   - "6-basic"
          #   - "9"
          #   - "9-basic"
          #   - "12"
          #   - "12-basic"
          #   - "18"
          #   - "18-basic"
          #   - "24"
          #   - "24-basic"
          #   - "36"
          #   - "36-basic"
          #   - "48"
          #   - "48-basic"
          #   - "54"
          #   - "54-basic"
          #   - "11"
          #   - "11-basic"
          # rates_11ac_mcs_map: <string>
          # rates_11ax_mcs_map: <string>
          # rates_11be_mcs_map: <string>
          # rates_11be_mcs_map_160: <string>
          # rates_11be_mcs_map_320: <string>
          # rates_11bg:
          #   - "1"
          #   - "1-basic"
          #   - "2"
          #   - "2-basic"
          #   - "5.5"
          #   - "5.5-basic"
          #   - "6"
          #   - "6-basic"
          #   - "9"
          #   - "9-basic"
          #   - "12"
          #   - "12-basic"
          #   - "18"
          #   - "18-basic"
          #   - "24"
          #   - "24-basic"
          #   - "36"
          #   - "36-basic"
          #   - "48"
          #   - "48-basic"
          #   - "54"
          #   - "54-basic"
          #   - "11"
          #   - "11-basic"
          # rates_11n_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/2"
          #   - "mcs11/2"
          #   - "mcs12/2"
          #   - "mcs13/2"
          #   - "mcs14/2"
          #   - "mcs15/2"
          # rates_11n_ss34:
          #   - "mcs16/3"
          #   - "mcs17/3"
          #   - "mcs18/3"
          #   - "mcs19/3"
          #   - "mcs20/3"
          #   - "mcs21/3"
          #   - "mcs22/3"
          #   - "mcs23/3"
          #   - "mcs24/4"
          #   - "mcs25/4"
          #   - "mcs26/4"
          #   - "mcs27/4"
          #   - "mcs28/4"
          #   - "mcs29/4"
          #   - "mcs30/4"
          #   - "mcs31/4"
          # roaming_acct_interim_update: <value in [disable, enable]>
          # sae_groups:
          #   - "1"
          #   - "2"
          #   - "5"
          #   - "14"
          #   - "15"
          #   - "16"
          #   - "17"
          #   - "18"
          #   - "19"
          #   - "20"
          #   - "21"
          #   - "27"
          #   - "28"
          #   - "29"
          #   - "30"
          #   - "31"
          # sae_h2e_only: <value in [disable, enable]>
          # sae_hnp_only: <value in [disable, enable]>
          # sae_password: <list or string>
          # sae_pk: <value in [disable, enable]>
          # sae_private_key: <string>
          # scan_botnet_connections: <value in [disable, block, monitor]>
          # schedule: <list or string>
          # secondary_wag_profile: <list or string>
          # security: <value in [None, wep64, wep128, ...]>
          # security_exempt_list: <list or string>
          # security_obsolete_option: <value in [disable, enable]>
          # security_redirect_url: <string>
          # selected_usergroups: <list or string>
          # split_tunneling: <value in [disable, enable]>
          # ssid: <string>
          # sticky_client_remove: <value in [disable, enable]>
          # sticky_client_threshold_2g: <string>
          # sticky_client_threshold_5g: <string>
          # sticky_client_threshold_6g: <string>
          # target_wake_time: <value in [disable, enable]>
          # tkip_counter_measure: <value in [disable, enable]>
          # tunnel_echo_interval: <integer>
          # tunnel_fallback_interval: <integer>
          # usergroup: <list or string>
          # utm_log: <value in [disable, enable]>
          # utm_profile: <list or string>
          # utm_status: <value in [disable, enable]>
          # vlan_auto: <value in [disable, enable]>
          # vlan_name:
          #   - name: <string>
          #     vlan_id: <integer>
          # vlan_pool:
          #   - _wtp_group: <string>
          #     id: <integer>
          #     wtp_group: <list or string>
          # vlan_pooling: <value in [wtp-group, round-robin, hash, ...]>
          # vlanid: <integer>
          # voice_enterprise: <value in [disable, enable]>
          # webfilter_profile: <list or string>
          # mac_filter_policy_other: <value in [deny, allow]>
          # mac_filter: <value in [disable, enable]>
          # rates_11ax_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/1"
          #   - "mcs9/1"
          #   - "mcs10/1"
          #   - "mcs11/1"
          #   - "mcs0/2"
          #   - "mcs1/2"
          #   - "mcs2/2"
          #   - "mcs3/2"
          #   - "mcs4/2"
          #   - "mcs5/2"
          #   - "mcs6/2"
          #   - "mcs7/2"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/2"
          #   - "mcs11/2"
          # rates_11ac_ss34:
          #   - "mcs0/3"
          #   - "mcs1/3"
          #   - "mcs2/3"
          #   - "mcs3/3"
          #   - "mcs4/3"
          #   - "mcs5/3"
          #   - "mcs6/3"
          #   - "mcs7/3"
          #   - "mcs8/3"
          #   - "mcs9/3"
          #   - "mcs0/4"
          #   - "mcs1/4"
          #   - "mcs2/4"
          #   - "mcs3/4"
          #   - "mcs4/4"
          #   - "mcs5/4"
          #   - "mcs6/4"
          #   - "mcs7/4"
          #   - "mcs8/4"
          #   - "mcs9/4"
          #   - "mcs10/3"
          #   - "mcs11/3"
          #   - "mcs10/4"
          #   - "mcs11/4"
          # rates_11ax_ss34:
          #   - "mcs0/3"
          #   - "mcs1/3"
          #   - "mcs2/3"
          #   - "mcs3/3"
          #   - "mcs4/3"
          #   - "mcs5/3"
          #   - "mcs6/3"
          #   - "mcs7/3"
          #   - "mcs8/3"
          #   - "mcs9/3"
          #   - "mcs10/3"
          #   - "mcs11/3"
          #   - "mcs0/4"
          #   - "mcs1/4"
          #   - "mcs2/4"
          #   - "mcs3/4"
          #   - "mcs4/4"
          #   - "mcs5/4"
          #   - "mcs6/4"
          #   - "mcs7/4"
          #   - "mcs8/4"
          #   - "mcs9/4"
          #   - "mcs10/4"
          #   - "mcs11/4"
          # rates_11ac_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/1"
          #   - "mcs9/1"
          #   - "mcs0/2"
          #   - "mcs1/2"
          #   - "mcs2/2"
          #   - "mcs3/2"
          #   - "mcs4/2"
          #   - "mcs5/2"
          #   - "mcs6/2"
          #   - "mcs7/2"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/1"
          #   - "mcs11/1"
          #   - "mcs10/2"
          #   - "mcs11/2"
          # mac_filter_list:
          #   - id: <integer>
          #     mac: <string>
          #     mac_filter_policy: <value in [deny, allow]>
          # mpsk_key:
          #   - comment: <string>
          #     concurrent_clients: <string>
          #     key_name: <string>
          #     mpsk_schedules: <list or string>
          #     passphrase: <list or string>
          # mpsk: <value in [disable, enable]>
          # mpsk_concurrent_clients: <integer>
          # acct_interim_interval: <integer>
          # captive_portal_radius_server: <string>
          # captive_portal_session_timeout_interval: <integer>
          # captive_portal_radius_secret: <list or string>
          # captive_portal_macauth_radius_secret: <list or string>
          # captive_portal_macauth_radius_server: <string>
          # _intf_ip_managed_by_fortiipam: <value in [disable, enable, inherit-global]>
          # _intf_managed_subnetwork_size: <value in [32, 64, 128, ...]>
          # domain_name_stripping: <value in [disable, enable]>
          # local_lan_partition: <value in [disable, enable]>
          # _intf_role: <value in [lan, wan, dmz, ...]>
          # called_station_id_type: <value in [mac, ip, apname]>
          # external_pre_auth: <value in [disable, enable]>
          # pre_auth: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_vap': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                '80211k': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '80211v': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_centmgmt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_dhcp_svr_id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_intf_allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm', 'fabric',
                        'speed-test'
                    ],
                    'elements': 'str'
                },
                '_intf_device-access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_intf_device-identification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_device-netscan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_intf_dhcp-relay-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                '_intf_dhcp6-relay-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_intf_dhcp6-relay-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp6-relay-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular'], 'type': 'str'},
                '_intf_ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_intf_ip6-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                '_intf_ip6-allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'any', 'fgfm', 'capwap'],
                    'elements': 'str'
                },
                '_intf_listen-forticlient-connection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_is_factory_setting': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                'access-control-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'additional-akms': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['akm6', 'akm24'], 'elements': 'str'},
                'address-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'address-group-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'allow', 'deny'], 'type': 'str'},
                'akm24-only': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'alias': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'antivirus-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'application-detection-engine': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-dscp-marking': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'application-report-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'atf-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['radius', 'usergroup', 'psk'], 'type': 'str'},
                'auth-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'auth-portal-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'beacon-advertising': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['name', 'model', 'serial-number'],
                    'elements': 'str'
                },
                'beacon-protection': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'broadcast-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'broadcast-suppression': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'dhcp', 'arp', 'dhcp2', 'arp2', 'netbios-ns', 'netbios-ds', 'arp3', 'dhcp-up', 'dhcp-down', 'arp-known', 'arp-unknown',
                        'arp-reply', 'ipv6', 'dhcp-starvation', 'arp-poison', 'all-other-mc', 'all-other-bc', 'arp-proxy', 'dhcp-ucast'
                    ],
                    'elements': 'str'
                },
                'bss-color-partial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bstm-disassociation-imminent': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bstm-load-balancing-disassoc-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bstm-rssi-disassoc-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'captive-portal': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal-ac-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'captive-portal-auth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'captive-portal-fw-accounting': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-address-enforcement': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-lease-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dhcp-option43-insertion': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option82-circuit-id-insertion': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'style-1', 'style-2', 'style-3'],
                    'type': 'str'
                },
                'dhcp-option82-insertion': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option82-remote-id-insertion': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'style-1'], 'type': 'str'},
                'dynamic-vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        '80211k': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '80211v': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_centmgmt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_dhcp_svr_id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_allowaccess': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm',
                                'fabric', 'speed-test'
                            ],
                            'elements': 'str'
                        },
                        '_intf_device-access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_device-identification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_device-netscan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp-relay-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_dhcp-relay-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp-relay-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                        '_intf_dhcp6-relay-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_dhcp6-relay-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp6-relay-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular'], 'type': 'str'},
                        '_intf_ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_ip6-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        '_intf_ip6-allowaccess': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'any', 'fgfm', 'capwap'],
                            'elements': 'str'
                        },
                        '_intf_listen-forticlient-connection': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        '_is_factory_setting': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'access-control-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'acct-interim-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'additional-akms': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['akm6', 'akm24'],
                            'elements': 'str'
                        },
                        'address-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'address-group-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'allow', 'deny'], 'type': 'str'},
                        'akm24-only': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'alias': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'antivirus-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'application-detection-engine': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'application-dscp-marking': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'application-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'application-report-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'atf-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['radius', 'usergroup', 'psk'], 'type': 'str'},
                        'auth-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'auth-portal-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'beacon-advertising': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['name', 'model', 'serial-number'],
                            'elements': 'str'
                        },
                        'beacon-protection': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'broadcast-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'broadcast-suppression': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'dhcp', 'arp', 'dhcp2', 'arp2', 'netbios-ns', 'netbios-ds', 'arp3', 'dhcp-up', 'dhcp-down', 'arp-known', 'arp-unknown',
                                'arp-reply', 'ipv6', 'dhcp-starvation', 'arp-poison', 'all-other-mc', 'all-other-bc', 'arp-proxy', 'dhcp-ucast'
                            ],
                            'elements': 'str'
                        },
                        'bss-color-partial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bstm-disassociation-imminent': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bstm-load-balancing-disassoc-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'bstm-rssi-disassoc-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'captive-portal': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'captive-portal-ac-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'captive-portal-auth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'captive-portal-fw-accounting': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'captive-portal-macauth-radius-secret': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'elements': 'str'
                        },
                        'captive-portal-macauth-radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'captive-portal-radius-secret': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'elements': 'str'
                        },
                        'captive-portal-radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'captive-portal-session-timeout-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'client-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'dhcp-address-enforcement': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-lease-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'dhcp-option43-insertion': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-option82-circuit-id-insertion': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'style-1', 'style-2', 'style-3'],
                            'type': 'str'
                        },
                        'dhcp-option82-insertion': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-option82-remote-id-insertion': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'style-1'],
                            'type': 'str'
                        },
                        'dynamic-vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'eap-reauth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'eap-reauth-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'eapol-key-retries': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'encrypt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['TKIP', 'AES', 'TKIP-AES'], 'type': 'str'},
                        'external-fast-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-logout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'external-web': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'external-web-format': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto-detect', 'no-query-string', 'partial-query-string'],
                            'type': 'str'
                        },
                        'fast-bss-transition': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fast-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ft-mobility-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ft-over-ds': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ft-r0-key-lifetime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'gas-comeback-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'gas-fragmentation-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'gtk-rekey': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'gtk-rekey-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'high-efficiency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'hotspot20-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'igmp-snooping': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'intra-vap-privacy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ips-sensor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ipv6-rules': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'drop-icmp6ra', 'drop-icmp6rs', 'drop-llmnr6', 'drop-icmp6mld2', 'drop-dhcp6s', 'drop-dhcp6c', 'ndp-proxy',
                                'drop-ns-dad', 'drop-ns-nondad'
                            ],
                            'elements': 'str'
                        },
                        'key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'keyindex': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'l3-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'l3-roaming-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['direct', 'indirect'], 'type': 'str'},
                        'ldpc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'tx', 'rx', 'rxtx'], 'type': 'str'},
                        'local-authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-bridging': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-lan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'local-standalone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-standalone-dns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-standalone-dns-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'local-standalone-nat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-switching': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-auth-bypass': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-called-station-delimiter': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-calling-station-delimiter': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-case': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                        'mac-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-filter-policy-other': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'mac-password-delimiter': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-username-delimiter': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'max-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'max-clients-ap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mbo': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mbo-cell-data-conn-pref': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['excluded', 'prefer-not', 'prefer-use'],
                            'type': 'str'
                        },
                        'me-disable-thresh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mesh-backhaul': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mpsk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mpsk-concurrent-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mpsk-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'mu-mimo': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'multicast-enhance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'multicast-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['0', '6000', '12000', '24000'], 'type': 'str'},
                        'nac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nac-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'nas-filter-rule': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'neighbor-report-dual-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'okc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'osen': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'owe-groups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['19', '20', '21'], 'elements': 'str'},
                        'owe-transition': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'owe-transition-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'passphrase': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'pmf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                        'pmf-assoc-comeback-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pmf-sa-query-retry-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'port-macauth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'radius', 'address-group'], 'type': 'str'},
                        'port-macauth-reauth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'port-macauth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'portal-message-override-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'portal-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': [
                                'auth', 'auth+disclaimer', 'disclaimer', 'email-collect', 'cmcc', 'cmcc-macauth', 'auth-mac', 'external-auth',
                                'external-macauth'
                            ],
                            'type': 'str'
                        },
                        'primary-wag-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'probe-resp-suppression': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'probe-resp-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'ptk-rekey': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ptk-rekey-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'qos-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'quarantine': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radio-2g-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'radio-5g-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'radio-sensitivity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-auth-block-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radius-mac-auth-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'radius-mac-auth-usergroups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'radius-mac-mpsk-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-mpsk-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'rates-11a': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic',
                                '24', '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ac-mcs-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'rates-11ac-ss12': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs0/2', 'mcs1/2',
                                'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/1', 'mcs11/1', 'mcs10/2',
                                'mcs11/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ac-ss34': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs0/4', 'mcs1/4',
                                'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/3', 'mcs11/3', 'mcs10/4',
                                'mcs11/4'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ax-mcs-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'rates-11ax-ss12': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs10/1', 'mcs11/1',
                                'mcs0/2', 'mcs1/2', 'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ax-ss34': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs10/3', 'mcs11/3',
                                'mcs0/4', 'mcs1/4', 'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/4', 'mcs11/4'
                            ],
                            'elements': 'str'
                        },
                        'rates-11be-mcs-map': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'rates-11be-mcs-map-160': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'rates-11be-mcs-map-320': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'rates-11bg': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic',
                                '24', '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                            ],
                            'elements': 'str'
                        },
                        'rates-11n-ss12': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2',
                                'mcs12/2', 'mcs13/2', 'mcs14/2', 'mcs15/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11n-ss34': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'mcs16/3', 'mcs17/3', 'mcs18/3', 'mcs19/3', 'mcs20/3', 'mcs21/3', 'mcs22/3', 'mcs23/3', 'mcs24/4', 'mcs25/4', 'mcs26/4',
                                'mcs27/4', 'mcs28/4', 'mcs29/4', 'mcs30/4', 'mcs31/4'
                            ],
                            'elements': 'str'
                        },
                        'roaming-acct-interim-update': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-groups': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31'],
                            'elements': 'str'
                        },
                        'sae-h2e-only': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-hnp-only': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'sae-pk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-private-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                        'scan-botnet-connections': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'schedule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'secondary-wag-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'security': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': [
                                'None', 'wep64', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open', 'wpa-personal', 'wpa-enterprise',
                                'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal', 'wpa2-only-enterprise',
                                'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal', 'wpa2-only-personal+captive-portal', 'osen',
                                'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae', 'wpa3-sae-transition', 'wpa3-only-enterprise',
                                'wpa3-enterprise-transition'
                            ],
                            'type': 'str'
                        },
                        'security-exempt-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'security-obsolete-option': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'security-redirect-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'selected-usergroups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'split-tunneling': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'sticky-client-remove': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sticky-client-threshold-2g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'sticky-client-threshold-5g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'sticky-client-threshold-6g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'target-wake-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tkip-counter-measure': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-echo-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'tunnel-fallback-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'usergroup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'utm-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'utm-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'utm-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'vlan-auto': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vlan-pooling': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['wtp-group', 'round-robin', 'hash', 'disable'],
                            'type': 'str'
                        },
                        'vlanid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'voice-enterprise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'webfilter-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        '_intf_ip-managed-by-fortiipam': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable', 'inherit-global'], 'type': 'str'},
                        '_intf_managed-subnetwork-size': {
                            'v_range': [['7.6.0', '']],
                            'choices': ['32', '64', '128', '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536'],
                            'type': 'str'
                        },
                        'domain-name-stripping': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-lan-partition': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_role': {'v_range': [['7.6.2', '']], 'choices': ['lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                        'called-station-id-type': {'v_range': [['7.6.2', '']], 'choices': ['mac', 'ip', 'apname'], 'type': 'str'},
                        'external-pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'eap-reauth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-reauth-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'eapol-key-retries': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'encrypt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['TKIP', 'AES', 'TKIP-AES'], 'type': 'str'},
                'external-fast-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-logout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'external-web': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'external-web-format': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['auto-detect', 'no-query-string', 'partial-query-string'],
                    'type': 'str'
                },
                'fast-bss-transition': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fast-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-mobility-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ft-over-ds': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-r0-key-lifetime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'gas-comeback-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'gas-fragmentation-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'gtk-rekey': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gtk-rekey-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'high-efficiency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hotspot20-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'igmp-snooping': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intra-vap-privacy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ips-sensor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-rules': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'drop-icmp6ra', 'drop-icmp6rs', 'drop-llmnr6', 'drop-icmp6mld2', 'drop-dhcp6s', 'drop-dhcp6c', 'ndp-proxy', 'drop-ns-dad',
                        'drop-ns-nondad'
                    ],
                    'elements': 'str'
                },
                'key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'keyindex': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'l3-roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'l3-roaming-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['direct', 'indirect'], 'type': 'str'},
                'ldpc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'tx', 'rx', 'rxtx'], 'type': 'str'},
                'local-authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-bridging': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-lan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'local-standalone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'local-standalone-nat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-auth-bypass': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-called-station-delimiter': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'mac-calling-station-delimiter': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'mac-case': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'mac-username-delimiter': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'max-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-clients-ap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mbo': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mbo-cell-data-conn-pref': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['excluded', 'prefer-not', 'prefer-use'],
                    'type': 'str'
                },
                'me-disable-thresh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mesh-backhaul': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mu-mimo': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-enhance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['0', '6000', '12000', '24000'], 'type': 'str'},
                'nac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nac-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'nas-filter-rule': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor-report-dual-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'okc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'osen': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-groups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['19', '20', '21'], 'elements': 'str'},
                'owe-transition': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-transition-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'passphrase': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'pmf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                'pmf-assoc-comeback-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'pmf-sa-query-retry-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'port-macauth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'radius', 'address-group'], 'type': 'str'},
                'port-macauth-reauth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'port-macauth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'portal-message-override-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'portal-message-overrides': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auth-disclaimer-page': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'auth-login-failed-page': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'auth-login-page': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'auth-reject-page': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    }
                },
                'portal-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'auth', 'auth+disclaimer', 'disclaimer', 'email-collect', 'cmcc', 'cmcc-macauth', 'auth-mac', 'external-auth',
                        'external-macauth'
                    ],
                    'type': 'str'
                },
                'primary-wag-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'probe-resp-suppression': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-resp-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ptk-rekey': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ptk-rekey-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'qos-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'quarantine': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radio-2g-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'radio-5g-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'radio-sensitivity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth-block-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'radius-mac-auth-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'radius-mac-auth-usergroups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'radius-mac-mpsk-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-mpsk-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'rates-11a': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-mcs-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'rates-11ax-mcs-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'rates-11be-mcs-map': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rates-11be-mcs-map-160': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rates-11be-mcs-map-320': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rates-11bg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss12': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2',
                        'mcs12/2', 'mcs13/2', 'mcs14/2', 'mcs15/2'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss34': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs16/3', 'mcs17/3', 'mcs18/3', 'mcs19/3', 'mcs20/3', 'mcs21/3', 'mcs22/3', 'mcs23/3', 'mcs24/4', 'mcs25/4', 'mcs26/4',
                        'mcs27/4', 'mcs28/4', 'mcs29/4', 'mcs30/4', 'mcs31/4'
                    ],
                    'elements': 'str'
                },
                'roaming-acct-interim-update': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-groups': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31'],
                    'elements': 'str'
                },
                'sae-h2e-only': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-hnp-only': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'sae-pk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-private-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'scan-botnet-connections': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'secondary-wag-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'security': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'None', 'wep64', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open', 'wpa-personal', 'wpa-enterprise',
                        'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal', 'wpa2-only-enterprise',
                        'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal', 'wpa2-only-personal+captive-portal', 'osen',
                        'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae', 'wpa3-sae-transition', 'wpa3-only-enterprise',
                        'wpa3-enterprise-transition'
                    ],
                    'type': 'str'
                },
                'security-exempt-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'security-obsolete-option': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'security-redirect-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'selected-usergroups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'split-tunneling': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sticky-client-remove': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sticky-client-threshold-2g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sticky-client-threshold-5g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sticky-client-threshold-6g': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'target-wake-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tkip-counter-measure': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-echo-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'tunnel-fallback-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'usergroup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'utm-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utm-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'utm-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-auto': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-name': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vlan-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'vlan-pool': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        '_wtp-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'wtp-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'vlan-pooling': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['wtp-group', 'round-robin', 'hash', 'disable'],
                    'type': 'str'
                },
                'vlanid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'voice-enterprise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mac-filter-policy-other': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'mac-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rates-11ax-ss12': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs10/1', 'mcs11/1',
                        'mcs0/2', 'mcs1/2', 'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss34': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs0/4', 'mcs1/4', 'mcs2/4',
                        'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/3', 'mcs11/3', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'rates-11ax-ss34': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs10/3', 'mcs11/3',
                        'mcs0/4', 'mcs1/4', 'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss12': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs0/2', 'mcs1/2', 'mcs2/2',
                        'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/1', 'mcs11/1', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'mac-filter-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'mac-filter-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mpsk-key': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'concurrent-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'key-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                        'mpsk-schedules': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'passphrase': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'mpsk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-concurrent-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'acct-interim-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'captive-portal-radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'captive-portal-session-timeout-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'captive-portal-radius-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'captive-portal-macauth-radius-secret': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'elements': 'str'
                },
                'captive-portal-macauth-radius-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                '_intf_ip-managed-by-fortiipam': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable', 'inherit-global'], 'type': 'str'},
                '_intf_managed-subnetwork-size': {
                    'v_range': [['7.6.0', '']],
                    'choices': ['32', '64', '128', '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536'],
                    'type': 'str'
                },
                'domain-name-stripping': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-lan-partition': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_role': {'v_range': [['7.6.2', '']], 'choices': ['lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                'called-station-id-type': {'v_range': [['7.6.2', '']], 'choices': ['mac', 'ip', 'apname'], 'type': 'str'},
                'external-pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_vap'),
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
