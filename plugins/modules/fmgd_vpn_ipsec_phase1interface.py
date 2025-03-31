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
module: fmgd_vpn_ipsec_phase1interface
short_description: Configure VPN remote gateway.
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
    vpn_ipsec_phase1interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            acct_verify:
                aliases: ['acct-verify']
                type: str
                description: Enable/disable verification of RADIUS accounting record.
                choices:
                    - 'disable'
                    - 'enable'
            add_gw_route:
                aliases: ['add-gw-route']
                type: str
                description: Enable/disable automatically add a route to the remote gateway.
                choices:
                    - 'disable'
                    - 'enable'
            add_route:
                aliases: ['add-route']
                type: str
                description: Enable/disable control addition of a route to peer destination selector.
                choices:
                    - 'disable'
                    - 'enable'
            aggregate_member:
                aliases: ['aggregate-member']
                type: str
                description: Enable/disable use as an aggregate member.
                choices:
                    - 'disable'
                    - 'enable'
            aggregate_weight:
                aliases: ['aggregate-weight']
                type: int
                description: Link weight for aggregate.
            assign_ip:
                aliases: ['assign-ip']
                type: str
                description: Enable/disable assignment of IP to IPsec interface via configuration method.
                choices:
                    - 'disable'
                    - 'enable'
            assign_ip_from:
                aliases: ['assign-ip-from']
                type: str
                description: Method by which the IP address will be assigned.
                choices:
                    - 'range'
                    - 'usrgrp'
                    - 'dhcp'
                    - 'name'
            authmethod:
                type: str
                description: Authentication method.
                choices:
                    - 'psk'
                    - 'rsa-signature'
                    - 'signature'
            authmethod_remote:
                aliases: ['authmethod-remote']
                type: str
                description: Authentication method
                choices:
                    - 'psk'
                    - 'signature'
            authpasswd:
                type: list
                elements: str
                description: XAuth password
            authusr:
                type: str
                description: XAuth user name.
            authusrgrp:
                type: list
                elements: str
                description: Authentication user group.
            auto_discovery_crossover:
                aliases: ['auto-discovery-crossover']
                type: str
                description: Allow/block set-up of short-cut tunnels between different network IDs.
                choices:
                    - 'block'
                    - 'allow'
            auto_discovery_forwarder:
                aliases: ['auto-discovery-forwarder']
                type: str
                description: Enable/disable forwarding auto-discovery short-cut messages.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_offer_interval:
                aliases: ['auto-discovery-offer-interval']
                type: int
                description: Interval between shortcut offer messages in seconds
            auto_discovery_psk:
                aliases: ['auto-discovery-psk']
                type: str
                description: Enable/disable use of pre-shared secrets for authentication of auto-discovery tunnels.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_receiver:
                aliases: ['auto-discovery-receiver']
                type: str
                description: Enable/disable accepting auto-discovery short-cut messages.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_sender:
                aliases: ['auto-discovery-sender']
                type: str
                description: Enable/disable sending auto-discovery short-cut messages.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_shortcuts:
                aliases: ['auto-discovery-shortcuts']
                type: str
                description: Control deletion of child short-cut tunnels when the parent tunnel goes down.
                choices:
                    - 'independent'
                    - 'dependent'
            auto_negotiate:
                aliases: ['auto-negotiate']
                type: str
                description: Enable/disable automatic initiation of IKE SA negotiation.
                choices:
                    - 'disable'
                    - 'enable'
            azure_ad_autoconnect:
                aliases: ['azure-ad-autoconnect']
                type: str
                description: Enable/disable Azure AD Auto-Connect for FortiClient.
                choices:
                    - 'disable'
                    - 'enable'
            backup_gateway:
                aliases: ['backup-gateway']
                type: list
                elements: str
                description: Instruct unity clients about the backup gateway address
            banner:
                type: str
                description: Message that unity client should display after connecting.
            cert_id_validation:
                aliases: ['cert-id-validation']
                type: str
                description: Enable/disable cross validation of peer ID and the identity in the peers certificate as specified in RFC 4945.
                choices:
                    - 'disable'
                    - 'enable'
            cert_peer_username_strip:
                aliases: ['cert-peer-username-strip']
                type: str
                description: Enable/disable domain stripping on certificate identity.
                choices:
                    - 'disable'
                    - 'enable'
            cert_peer_username_validation:
                aliases: ['cert-peer-username-validation']
                type: str
                description: Enable/disable cross validation of peer username and the identity in the peers certificate.
                choices:
                    - 'othername'
                    - 'rfc822name'
                    - 'cn'
                    - 'none'
            cert_trust_store:
                aliases: ['cert-trust-store']
                type: str
                description: CA certificate trust store.
                choices:
                    - 'local'
                    - 'ems'
            certificate:
                type: list
                elements: str
                description: The names of up to 4 signed personal certificates.
            childless_ike:
                aliases: ['childless-ike']
                type: str
                description: Enable/disable childless IKEv2 initiation
                choices:
                    - 'disable'
                    - 'enable'
            client_auto_negotiate:
                aliases: ['client-auto-negotiate']
                type: str
                description: Enable/disable allowing the VPN client to bring up the tunnel when there is no traffic.
                choices:
                    - 'disable'
                    - 'enable'
            client_keep_alive:
                aliases: ['client-keep-alive']
                type: str
                description: Enable/disable allowing the VPN client to keep the tunnel up when there is no traffic.
                choices:
                    - 'disable'
                    - 'enable'
            client_resume:
                aliases: ['client-resume']
                type: str
                description: Enable/disable resumption of offline FortiClient sessions.
                choices:
                    - 'disable'
                    - 'enable'
            client_resume_interval:
                aliases: ['client-resume-interval']
                type: int
                description: Maximum time in seconds during which a VPN client may resume using a tunnel after a client PC has entered sleep mode or te...
            comments:
                type: str
                description: Comment.
            default_gw:
                aliases: ['default-gw']
                type: str
                description: IPv4 address of default route gateway to use for traffic exiting the interface.
            default_gw_priority:
                aliases: ['default-gw-priority']
                type: int
                description: Priority for default gateway route.
            dev_id:
                aliases: ['dev-id']
                type: str
                description: Device ID carried by the device ID notification.
            dev_id_notification:
                aliases: ['dev-id-notification']
                type: str
                description: Enable/disable device ID notification.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_ra_giaddr:
                aliases: ['dhcp-ra-giaddr']
                type: str
                description: Relay agent gateway IP address to use in the giaddr field of DHCP requests.
            dhcp6_ra_linkaddr:
                aliases: ['dhcp6-ra-linkaddr']
                type: str
                description: Relay agent IPv6 link address to use in DHCP6 requests.
            dhgrp:
                type: list
                elements: str
                description: DH group.
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
                    - '32'
            digital_signature_auth:
                aliases: ['digital-signature-auth']
                type: str
                description: Enable/disable IKEv2 Digital Signature Authentication
                choices:
                    - 'disable'
                    - 'enable'
            distance:
                type: int
                description: Distance for routes added by IKE
            dns_mode:
                aliases: ['dns-mode']
                type: str
                description: DNS server mode.
                choices:
                    - 'auto'
                    - 'manual'
            domain:
                type: str
                description: Instruct unity clients about the single default DNS domain.
            dpd:
                type: str
                description: Dead Peer Detection mode.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'on-idle'
                    - 'on-demand'
            dpd_retrycount:
                aliases: ['dpd-retrycount']
                type: int
                description: Number of DPD retry attempts.
            dpd_retryinterval:
                aliases: ['dpd-retryinterval']
                type: list
                elements: int
                description: DPD retry interval.
            eap:
                type: str
                description: Enable/disable IKEv2 EAP authentication.
                choices:
                    - 'disable'
                    - 'enable'
            eap_cert_auth:
                aliases: ['eap-cert-auth']
                type: str
                description: Enable/disable peer certificate authentication in addition to EAP if peer is a FortiClient endpoint.
                choices:
                    - 'disable'
                    - 'enable'
            eap_exclude_peergrp:
                aliases: ['eap-exclude-peergrp']
                type: list
                elements: str
                description: Peer group excluded from EAP authentication.
            eap_identity:
                aliases: ['eap-identity']
                type: str
                description: IKEv2 EAP peer identity type.
                choices:
                    - 'use-id-payload'
                    - 'send-request'
            ems_sn_check:
                aliases: ['ems-sn-check']
                type: str
                description: Enable/disable verification of EMS serial number.
                choices:
                    - 'use-global'
                    - 'enable'
                    - 'disable'
            encap_local_gw4:
                aliases: ['encap-local-gw4']
                type: str
                description: Local IPv4 address of GRE/VXLAN tunnel.
            encap_local_gw6:
                aliases: ['encap-local-gw6']
                type: str
                description: Local IPv6 address of GRE/VXLAN tunnel.
            encap_remote_gw4:
                aliases: ['encap-remote-gw4']
                type: str
                description: Remote IPv4 address of GRE/VXLAN tunnel.
            encap_remote_gw6:
                aliases: ['encap-remote-gw6']
                type: str
                description: Remote IPv6 address of GRE/VXLAN tunnel.
            encapsulation:
                type: str
                description: Enable/disable GRE/VXLAN/VPNID encapsulation.
                choices:
                    - 'none'
                    - 'gre'
                    - 'vxlan'
                    - 'vpn-id-ipip'
            encapsulation_address:
                aliases: ['encapsulation-address']
                type: str
                description: Source for GRE/VXLAN tunnel address.
                choices:
                    - 'ike'
                    - 'ipv4'
                    - 'ipv6'
            enforce_unique_id:
                aliases: ['enforce-unique-id']
                type: str
                description: Enable/disable peer ID uniqueness check.
                choices:
                    - 'disable'
                    - 'keep-new'
                    - 'keep-old'
            esn:
                type: str
                description: Extended sequence number
                choices:
                    - 'disable'
                    - 'require'
                    - 'allow'
            exchange_fgt_device_id:
                aliases: ['exchange-fgt-device-id']
                type: str
                description: Enable/disable device identifier exchange with peer FortiGate units for use of VPN monitor data by FortiManager.
                choices:
                    - 'disable'
                    - 'enable'
            exchange_interface_ip:
                aliases: ['exchange-interface-ip']
                type: str
                description: Enable/disable exchange of IPsec interface IP address.
                choices:
                    - 'disable'
                    - 'enable'
            exchange_ip_addr4:
                aliases: ['exchange-ip-addr4']
                type: str
                description: IPv4 address to exchange with peers.
            exchange_ip_addr6:
                aliases: ['exchange-ip-addr6']
                type: str
                description: IPv6 address to exchange with peers.
            fallback_tcp_threshold:
                aliases: ['fallback-tcp-threshold']
                type: int
                description: Timeout in seconds before falling back IKE/IPsec traffic to tcp.
            fec_base:
                aliases: ['fec-base']
                type: int
                description: Number of base Forward Error Correction packets
            fec_codec:
                aliases: ['fec-codec']
                type: str
                description: Forward Error Correction encoding/decoding algorithm.
                choices:
                    - 'rs'
                    - 'xor'
            fec_egress:
                aliases: ['fec-egress']
                type: str
                description: Enable/disable Forward Error Correction for egress IPsec traffic.
                choices:
                    - 'disable'
                    - 'enable'
            fec_health_check:
                aliases: ['fec-health-check']
                type: list
                elements: str
                description: SD-WAN health check.
            fec_ingress:
                aliases: ['fec-ingress']
                type: str
                description: Enable/disable Forward Error Correction for ingress IPsec traffic.
                choices:
                    - 'disable'
                    - 'enable'
            fec_mapping_profile:
                aliases: ['fec-mapping-profile']
                type: list
                elements: str
                description: Forward Error Correction
            fec_receive_timeout:
                aliases: ['fec-receive-timeout']
                type: int
                description: Timeout in milliseconds before dropping Forward Error Correction packets
            fec_redundant:
                aliases: ['fec-redundant']
                type: int
                description: Number of redundant Forward Error Correction packets
            fec_send_timeout:
                aliases: ['fec-send-timeout']
                type: int
                description: Timeout in milliseconds before sending Forward Error Correction packets
            fgsp_sync:
                aliases: ['fgsp-sync']
                type: str
                description: Enable/disable IPsec syncing of tunnels for FGSP IPsec.
                choices:
                    - 'disable'
                    - 'enable'
            fortinet_esp:
                aliases: ['fortinet-esp']
                type: str
                description: Enable/disable Fortinet ESP encapsulaton.
                choices:
                    - 'disable'
                    - 'enable'
            fragmentation:
                type: str
                description: Enable/disable fragment IKE message on re-transmission.
                choices:
                    - 'disable'
                    - 'enable'
            fragmentation_mtu:
                aliases: ['fragmentation-mtu']
                type: int
                description: IKE fragmentation MTU
            group_authentication:
                aliases: ['group-authentication']
                type: str
                description: Enable/disable IKEv2 IDi group authentication.
                choices:
                    - 'disable'
                    - 'enable'
            group_authentication_secret:
                aliases: ['group-authentication-secret']
                type: list
                elements: str
                description: Password for IKEv2 ID group authentication.
            ha_sync_esp_seqno:
                aliases: ['ha-sync-esp-seqno']
                type: str
                description: Enable/disable sequence number jump ahead for IPsec HA.
                choices:
                    - 'disable'
                    - 'enable'
            idle_timeout:
                aliases: ['idle-timeout']
                type: str
                description: Enable/disable IPsec tunnel idle timeout.
                choices:
                    - 'disable'
                    - 'enable'
            idle_timeoutinterval:
                aliases: ['idle-timeoutinterval']
                type: int
                description: IPsec tunnel idle timeout in minutes
            ike_version:
                aliases: ['ike-version']
                type: str
                description: IKE protocol version.
                choices:
                    - '1'
                    - '2'
            inbound_dscp_copy:
                aliases: ['inbound-dscp-copy']
                type: str
                description: Enable/disable copy the dscp in the ESP header to the inner IP Header.
                choices:
                    - 'disable'
                    - 'enable'
            include_local_lan:
                aliases: ['include-local-lan']
                type: str
                description: Enable/disable allow local LAN access on unity clients.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Local physical, aggregate, or VLAN outgoing interface.
            internal_domain_list:
                aliases: ['internal-domain-list']
                type: list
                elements: str
                description: One or more internal domain names in quotes separated by spaces.
            ip_delay_interval:
                aliases: ['ip-delay-interval']
                type: int
                description: IP address reuse delay interval in seconds
            ip_fragmentation:
                aliases: ['ip-fragmentation']
                type: str
                description: Determine whether IP packets are fragmented before or after IPsec encapsulation.
                choices:
                    - 'pre-encapsulation'
                    - 'post-encapsulation'
            ip_version:
                aliases: ['ip-version']
                type: str
                description: IP version to use for VPN interface.
                choices:
                    - '4'
                    - '6'
            ipsec_tunnel_slot:
                aliases: ['ipsec-tunnel-slot']
                type: str
                description: Slot at which IPsec tunnel will be establishd.
                choices:
                    - 'master'
                    - 'auto'
                    - 'FPC1'
                    - 'FPC2'
                    - 'FPC3'
                    - 'FPC4'
                    - 'FPC5'
                    - 'FPC6'
                    - 'FPC7'
                    - 'FPC8'
                    - 'FPC9'
                    - 'FPC10'
                    - 'FPM3'
                    - 'FPM4'
                    - 'FPM5'
                    - 'FPM6'
                    - 'FPM7'
                    - 'FPM8'
                    - 'FPM9'
                    - 'FPM10'
                    - 'FPM11'
                    - 'FPM12'
            ipv4_dns_server1:
                aliases: ['ipv4-dns-server1']
                type: str
                description: IPv4 DNS server 1.
            ipv4_dns_server2:
                aliases: ['ipv4-dns-server2']
                type: str
                description: IPv4 DNS server 2.
            ipv4_dns_server3:
                aliases: ['ipv4-dns-server3']
                type: str
                description: IPv4 DNS server 3.
            ipv4_end_ip:
                aliases: ['ipv4-end-ip']
                type: str
                description: End of IPv4 range.
            ipv4_exclude_range:
                aliases: ['ipv4-exclude-range']
                type: list
                elements: dict
                description: Ipv4 exclude range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End of IPv4 exclusive range.
                    id:
                        type: int
                        description: ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IPv4 exclusive range.
            ipv4_name:
                aliases: ['ipv4-name']
                type: list
                elements: str
                description: IPv4 address name.
            ipv4_netmask:
                aliases: ['ipv4-netmask']
                type: str
                description: IPv4 Netmask.
            ipv4_split_exclude:
                aliases: ['ipv4-split-exclude']
                type: list
                elements: str
                description: IPv4 subnets that should not be sent over the IPsec tunnel.
            ipv4_split_include:
                aliases: ['ipv4-split-include']
                type: list
                elements: str
                description: IPv4 split-include subnets.
            ipv4_start_ip:
                aliases: ['ipv4-start-ip']
                type: str
                description: Start of IPv4 range.
            ipv4_wins_server1:
                aliases: ['ipv4-wins-server1']
                type: str
                description: WINS server 1.
            ipv4_wins_server2:
                aliases: ['ipv4-wins-server2']
                type: str
                description: WINS server 2.
            ipv6_dns_server1:
                aliases: ['ipv6-dns-server1']
                type: str
                description: IPv6 DNS server 1.
            ipv6_dns_server2:
                aliases: ['ipv6-dns-server2']
                type: str
                description: IPv6 DNS server 2.
            ipv6_dns_server3:
                aliases: ['ipv6-dns-server3']
                type: str
                description: IPv6 DNS server 3.
            ipv6_end_ip:
                aliases: ['ipv6-end-ip']
                type: str
                description: End of IPv6 range.
            ipv6_exclude_range:
                aliases: ['ipv6-exclude-range']
                type: list
                elements: dict
                description: Ipv6 exclude range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End of IPv6 exclusive range.
                    id:
                        type: int
                        description: ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IPv6 exclusive range.
            ipv6_name:
                aliases: ['ipv6-name']
                type: list
                elements: str
                description: IPv6 address name.
            ipv6_prefix:
                aliases: ['ipv6-prefix']
                type: int
                description: IPv6 prefix.
            ipv6_split_exclude:
                aliases: ['ipv6-split-exclude']
                type: list
                elements: str
                description: IPv6 subnets that should not be sent over the IPsec tunnel.
            ipv6_split_include:
                aliases: ['ipv6-split-include']
                type: list
                elements: str
                description: IPv6 split-include subnets.
            ipv6_start_ip:
                aliases: ['ipv6-start-ip']
                type: str
                description: Start of IPv6 range.
            keepalive:
                type: int
                description: NAT-T keep alive interval.
            keylife:
                type: int
                description: Time to wait in seconds before phase 1 encryption key expires.
            kms:
                type: list
                elements: str
                description: Key Management Services server.
            link_cost:
                aliases: ['link-cost']
                type: int
                description: VPN tunnel underlay link cost.
            local_gw:
                aliases: ['local-gw']
                type: str
                description: IPv4 address of the local gateways external interface.
            local_gw6:
                aliases: ['local-gw6']
                type: str
                description: IPv6 address of the local gateways external interface.
            localid:
                type: str
                description: Local ID.
            localid_type:
                aliases: ['localid-type']
                type: str
                description: Local ID type.
                choices:
                    - 'auto'
                    - 'fqdn'
                    - 'user-fqdn'
                    - 'keyid'
                    - 'address'
                    - 'asn1dn'
            loopback_asymroute:
                aliases: ['loopback-asymroute']
                type: str
                description: Enable/disable asymmetric routing for IKE traffic on loopback interface.
                choices:
                    - 'disable'
                    - 'enable'
            mesh_selector_type:
                aliases: ['mesh-selector-type']
                type: str
                description: Add selectors containing subsets of the configuration depending on traffic.
                choices:
                    - 'disable'
                    - 'subnet'
                    - 'host'
            mode:
                type: str
                description: The ID protection mode used to establish a secure channel.
                choices:
                    - 'main'
                    - 'aggressive'
            mode_cfg:
                aliases: ['mode-cfg']
                type: str
                description: Enable/disable configuration method.
                choices:
                    - 'disable'
                    - 'enable'
            mode_cfg_allow_client_selector:
                aliases: ['mode-cfg-allow-client-selector']
                type: str
                description: Enable/disable mode-cfg client to use custom phase2 selectors.
                choices:
                    - 'disable'
                    - 'enable'
            monitor:
                type: list
                elements: str
                description: IPsec interface as backup for primary interface.
            monitor_hold_down_delay:
                aliases: ['monitor-hold-down-delay']
                type: int
                description: Time to wait in seconds before recovery once primary re-establishes.
            monitor_hold_down_time:
                aliases: ['monitor-hold-down-time']
                type: str
                description: Time of day at which to fail back to primary after it re-establishes.
            monitor_hold_down_type:
                aliases: ['monitor-hold-down-type']
                type: str
                description: Recovery time method when primary interface re-establishes.
                choices:
                    - 'immediate'
                    - 'delay'
                    - 'time'
            monitor_hold_down_weekday:
                aliases: ['monitor-hold-down-weekday']
                type: str
                description: Day of the week to recover once primary re-establishes.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
                    - 'everyday'
            monitor_min:
                aliases: ['monitor-min']
                type: int
                description: Minimum number of links to become degraded before activating this interface.
            name:
                type: str
                description: IPsec remote gateway name.
                required: true
            nattraversal:
                type: str
                description: Enable/disable NAT traversal.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'forced'
            negotiate_timeout:
                aliases: ['negotiate-timeout']
                type: int
                description: IKE SA negotiation timeout in seconds
            net_device:
                aliases: ['net-device']
                type: str
                description: Enable/disable kernel device creation.
                choices:
                    - 'disable'
                    - 'enable'
            network_id:
                aliases: ['network-id']
                type: int
                description: VPN gateway network ID.
            network_overlay:
                aliases: ['network-overlay']
                type: str
                description: Enable/disable network overlays.
                choices:
                    - 'disable'
                    - 'enable'
            npu_offload:
                aliases: ['npu-offload']
                type: str
                description: Enable/disable offloading NPU.
                choices:
                    - 'disable'
                    - 'enable'
            packet_redistribution:
                aliases: ['packet-redistribution']
                type: str
                description: Enable/disable packet distribution
                choices:
                    - 'disable'
                    - 'enable'
            passive_mode:
                aliases: ['passive-mode']
                type: str
                description: Enable/disable IPsec passive mode for static tunnels.
                choices:
                    - 'disable'
                    - 'enable'
            peer:
                type: list
                elements: str
                description: Accept this peer certificate.
            peergrp:
                type: list
                elements: str
                description: Accept this peer certificate group.
            peerid:
                type: str
                description: Accept this peer identity.
            peertype:
                type: str
                description: Accept this peer type.
                choices:
                    - 'any'
                    - 'one'
                    - 'dialup'
                    - 'peer'
                    - 'peergrp'
            ppk:
                type: str
                description: Enable/disable IKEv2 Postquantum Preshared Key
                choices:
                    - 'disable'
                    - 'allow'
                    - 'require'
            ppk_identity:
                aliases: ['ppk-identity']
                type: str
                description: IKEv2 Postquantum Preshared Key Identity.
            ppk_secret:
                aliases: ['ppk-secret']
                type: list
                elements: str
                description: IKEv2 Postquantum Preshared Key
            priority:
                type: int
                description: Priority for routes added by IKE
            proposal:
                type: str
                description: Phase1 proposal.
                choices:
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
                    - 'aes128gcm-prfsha1'
                    - 'aes128gcm-prfsha256'
                    - 'aes128gcm-prfsha384'
                    - 'aes128gcm-prfsha512'
                    - 'aes256gcm-prfsha1'
                    - 'aes256gcm-prfsha256'
                    - 'aes256gcm-prfsha384'
                    - 'aes256gcm-prfsha512'
                    - 'chacha20poly1305-prfsha1'
                    - 'chacha20poly1305-prfsha256'
                    - 'chacha20poly1305-prfsha384'
                    - 'chacha20poly1305-prfsha512'
            psksecret:
                type: list
                elements: str
                description: Pre-shared secret for PSK authentication
            psksecret_remote:
                aliases: ['psksecret-remote']
                type: list
                elements: str
                description: Pre-shared secret for remote side PSK authentication
            qkd:
                type: str
                description: Enable/disable use of Quantum Key Distribution
                choices:
                    - 'disable'
                    - 'allow'
                    - 'require'
            qkd_profile:
                aliases: ['qkd-profile']
                type: list
                elements: str
                description: Quantum Key Distribution
            reauth:
                type: str
                description: Enable/disable re-authentication upon IKE SA lifetime expiration.
                choices:
                    - 'disable'
                    - 'enable'
            rekey:
                type: str
                description: Enable/disable phase1 rekey.
                choices:
                    - 'disable'
                    - 'enable'
            remote_gw:
                aliases: ['remote-gw']
                type: str
                description: IPv4 address of the remote gateways external interface.
            remote_gw_country:
                aliases: ['remote-gw-country']
                type: str
                description: IPv4 addresses associated to a specific country.
            remote_gw_end_ip:
                aliases: ['remote-gw-end-ip']
                type: str
                description: Last IPv4 address in the range.
            remote_gw_match:
                aliases: ['remote-gw-match']
                type: str
                description: Set type of IPv4 remote gateway address matching.
                choices:
                    - 'any'
                    - 'ipmask'
                    - 'iprange'
                    - 'geography'
                    - 'ztna'
            remote_gw_start_ip:
                aliases: ['remote-gw-start-ip']
                type: str
                description: First IPv4 address in the range.
            remote_gw_subnet:
                aliases: ['remote-gw-subnet']
                type: list
                elements: str
                description: IPv4 address and subnet mask.
            remote_gw6:
                aliases: ['remote-gw6']
                type: str
                description: IPv6 address of the remote gateways external interface.
            remote_gw6_country:
                aliases: ['remote-gw6-country']
                type: str
                description: IPv6 addresses associated to a specific country.
            remote_gw6_end_ip:
                aliases: ['remote-gw6-end-ip']
                type: str
                description: Last IPv6 address in the range.
            remote_gw6_match:
                aliases: ['remote-gw6-match']
                type: str
                description: Set type of IPv6 remote gateway address matching.
                choices:
                    - 'any'
                    - 'iprange'
                    - 'geography'
                    - 'ipprefix'
            remote_gw6_start_ip:
                aliases: ['remote-gw6-start-ip']
                type: str
                description: First IPv6 address in the range.
            remote_gw6_subnet:
                aliases: ['remote-gw6-subnet']
                type: str
                description: IPv6 address and prefix.
            remotegw_ddns:
                aliases: ['remotegw-ddns']
                type: str
                description: Domain name of remote gateway.
            rsa_signature_format:
                aliases: ['rsa-signature-format']
                type: str
                description: Digital Signature Authentication RSA signature format.
                choices:
                    - 'pkcs1'
                    - 'pss'
            rsa_signature_hash_override:
                aliases: ['rsa-signature-hash-override']
                type: str
                description: Enable/disable IKEv2 RSA signature hash algorithm override.
                choices:
                    - 'disable'
                    - 'enable'
            save_password:
                aliases: ['save-password']
                type: str
                description: Enable/disable saving XAuth username and password on VPN clients.
                choices:
                    - 'disable'
                    - 'enable'
            send_cert_chain:
                aliases: ['send-cert-chain']
                type: str
                description: Enable/disable sending certificate chain.
                choices:
                    - 'disable'
                    - 'enable'
            signature_hash_alg:
                aliases: ['signature-hash-alg']
                type: list
                elements: str
                description: Digital Signature Authentication hash algorithms.
                choices:
                    - 'sha1'
                    - 'sha2-256'
                    - 'sha2-384'
                    - 'sha2-512'
            split_include_service:
                aliases: ['split-include-service']
                type: list
                elements: str
                description: Split-include services.
            suite_b:
                aliases: ['suite-b']
                type: str
                description: Use Suite-B.
                choices:
                    - 'disable'
                    - 'suite-b-gcm-128'
                    - 'suite-b-gcm-256'
            transit_gateway:
                aliases: ['transit-gateway']
                type: str
                description: IPsec tunnel created by autoscaling to be used as a transit gateway.
                choices:
                    - 'disable'
                    - 'enable'
            transport:
                type: str
                description: Set IKE transport protocol.
                choices:
                    - 'udp'
                    - 'tcp'
                    - 'udp-fallback-tcp'
                    - 'auto'
            type:
                type: str
                description: Remote gateway type.
                choices:
                    - 'static'
                    - 'dynamic'
                    - 'ddns'
            unity_support:
                aliases: ['unity-support']
                type: str
                description: Enable/disable support for Cisco UNITY Configuration Method extensions.
                choices:
                    - 'disable'
                    - 'enable'
            usrgrp:
                type: list
                elements: str
                description: User group name for dialup peers.
            vni:
                type: int
                description: VNI of VXLAN tunnel.
            wizard_type:
                aliases: ['wizard-type']
                type: str
                description: GUI VPN Wizard Type.
                choices:
                    - 'custom'
                    - 'dialup-forticlient'
                    - 'dialup-ios'
                    - 'dialup-android'
                    - 'dialup-cisco'
                    - 'static-fortigate'
                    - 'static-cisco'
                    - 'dialup-windows'
                    - 'dialup-fortigate'
                    - 'dialup-cisco-fw'
                    - 'simplified-static-fortigate'
                    - 'hub-fortigate-auto-discovery'
                    - 'spoke-fortigate-auto-discovery'
                    - 'static-fortiproxy'
                    - 'dialup-fortiproxy'
                    - 'simplified-static-fortiproxy'
                    - 'hub-fortiproxy-auto-discovery'
                    - 'spoke-fortiproxy-auto-discovery'
                    - 'fabric-overlay-orchestrator'
            xauthtype:
                type: str
                description: XAuth type.
                choices:
                    - 'disable'
                    - 'client'
                    - 'pap'
                    - 'chap'
                    - 'auto'
            forticlient_enforcement:
                aliases: ['forticlient-enforcement']
                type: str
                description: Enable/disable FortiClient enforcement.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_search:
                aliases: ['tunnel-search']
                type: str
                description: Tunnel search method for when the interface is shared.
                choices:
                    - 'selectors'
                    - 'nexthop'
            addke1:
                type: list
                elements: str
                description: ADDKE1 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke2:
                type: list
                elements: str
                description: ADDKE2 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke3:
                type: list
                elements: str
                description: ADDKE3 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke4:
                type: list
                elements: str
                description: ADDKE4 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke5:
                type: list
                elements: str
                description: ADDKE5 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke6:
                type: list
                elements: str
                description: ADDKE6 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke7:
                type: list
                elements: str
                description: ADDKE7 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            auto_transport_threshold:
                aliases: ['auto-transport-threshold']
                type: int
                description: Timeout in seconds before falling back to next transport protocol.
            ipv6_auto_linklocal:
                aliases: ['ipv6-auto-linklocal']
                type: str
                description: Enable/disable auto generation of IPv6 link-local address using last 8 bytes of mode-cfg assigned IPv6 address.
                choices:
                    - 'disable'
                    - 'enable'
            remote_gw_ztna_tags:
                aliases: ['remote-gw-ztna-tags']
                type: list
                elements: str
                description: IPv4 ZTNA posture tags.
            shared_idle_timeout:
                aliases: ['shared-idle-timeout']
                type: str
                description: Enable/disable IPsec tunnel shared idle timeout.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_dialup_placeholder:
                aliases: ['auto-discovery-dialup-placeholder']
                type: str
                description: Control if this dynamic gateway is used for shortcut connections only.
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
    - name: Configure VPN remote gateway.
      fortinet.fmgdevice.fmgd_vpn_ipsec_phase1interface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_ipsec_phase1interface:
          name: "your value" # Required variable, string
          # acct_verify: <value in [disable, enable]>
          # add_gw_route: <value in [disable, enable]>
          # add_route: <value in [disable, enable]>
          # aggregate_member: <value in [disable, enable]>
          # aggregate_weight: <integer>
          # assign_ip: <value in [disable, enable]>
          # assign_ip_from: <value in [range, usrgrp, dhcp, ...]>
          # authmethod: <value in [psk, rsa-signature, signature]>
          # authmethod_remote: <value in [psk, signature]>
          # authpasswd: <list or string>
          # authusr: <string>
          # authusrgrp: <list or string>
          # auto_discovery_crossover: <value in [block, allow]>
          # auto_discovery_forwarder: <value in [disable, enable]>
          # auto_discovery_offer_interval: <integer>
          # auto_discovery_psk: <value in [disable, enable]>
          # auto_discovery_receiver: <value in [disable, enable]>
          # auto_discovery_sender: <value in [disable, enable]>
          # auto_discovery_shortcuts: <value in [independent, dependent]>
          # auto_negotiate: <value in [disable, enable]>
          # azure_ad_autoconnect: <value in [disable, enable]>
          # backup_gateway: <list or string>
          # banner: <string>
          # cert_id_validation: <value in [disable, enable]>
          # cert_peer_username_strip: <value in [disable, enable]>
          # cert_peer_username_validation: <value in [othername, rfc822name, cn, ...]>
          # cert_trust_store: <value in [local, ems]>
          # certificate: <list or string>
          # childless_ike: <value in [disable, enable]>
          # client_auto_negotiate: <value in [disable, enable]>
          # client_keep_alive: <value in [disable, enable]>
          # client_resume: <value in [disable, enable]>
          # client_resume_interval: <integer>
          # comments: <string>
          # default_gw: <string>
          # default_gw_priority: <integer>
          # dev_id: <string>
          # dev_id_notification: <value in [disable, enable]>
          # dhcp_ra_giaddr: <string>
          # dhcp6_ra_linkaddr: <string>
          # dhgrp:
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
          #   - "32"
          # digital_signature_auth: <value in [disable, enable]>
          # distance: <integer>
          # dns_mode: <value in [auto, manual]>
          # domain: <string>
          # dpd: <value in [disable, enable, on-idle, ...]>
          # dpd_retrycount: <integer>
          # dpd_retryinterval: <list or integer>
          # eap: <value in [disable, enable]>
          # eap_cert_auth: <value in [disable, enable]>
          # eap_exclude_peergrp: <list or string>
          # eap_identity: <value in [use-id-payload, send-request]>
          # ems_sn_check: <value in [use-global, enable, disable]>
          # encap_local_gw4: <string>
          # encap_local_gw6: <string>
          # encap_remote_gw4: <string>
          # encap_remote_gw6: <string>
          # encapsulation: <value in [none, gre, vxlan, ...]>
          # encapsulation_address: <value in [ike, ipv4, ipv6]>
          # enforce_unique_id: <value in [disable, keep-new, keep-old]>
          # esn: <value in [disable, require, allow]>
          # exchange_fgt_device_id: <value in [disable, enable]>
          # exchange_interface_ip: <value in [disable, enable]>
          # exchange_ip_addr4: <string>
          # exchange_ip_addr6: <string>
          # fallback_tcp_threshold: <integer>
          # fec_base: <integer>
          # fec_codec: <value in [rs, xor]>
          # fec_egress: <value in [disable, enable]>
          # fec_health_check: <list or string>
          # fec_ingress: <value in [disable, enable]>
          # fec_mapping_profile: <list or string>
          # fec_receive_timeout: <integer>
          # fec_redundant: <integer>
          # fec_send_timeout: <integer>
          # fgsp_sync: <value in [disable, enable]>
          # fortinet_esp: <value in [disable, enable]>
          # fragmentation: <value in [disable, enable]>
          # fragmentation_mtu: <integer>
          # group_authentication: <value in [disable, enable]>
          # group_authentication_secret: <list or string>
          # ha_sync_esp_seqno: <value in [disable, enable]>
          # idle_timeout: <value in [disable, enable]>
          # idle_timeoutinterval: <integer>
          # ike_version: <value in [1, 2]>
          # inbound_dscp_copy: <value in [disable, enable]>
          # include_local_lan: <value in [disable, enable]>
          # interface: <list or string>
          # internal_domain_list: <list or string>
          # ip_delay_interval: <integer>
          # ip_fragmentation: <value in [pre-encapsulation, post-encapsulation]>
          # ip_version: <value in [4, 6]>
          # ipsec_tunnel_slot: <value in [master, auto, FPC1, ...]>
          # ipv4_dns_server1: <string>
          # ipv4_dns_server2: <string>
          # ipv4_dns_server3: <string>
          # ipv4_end_ip: <string>
          # ipv4_exclude_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          # ipv4_name: <list or string>
          # ipv4_netmask: <string>
          # ipv4_split_exclude: <list or string>
          # ipv4_split_include: <list or string>
          # ipv4_start_ip: <string>
          # ipv4_wins_server1: <string>
          # ipv4_wins_server2: <string>
          # ipv6_dns_server1: <string>
          # ipv6_dns_server2: <string>
          # ipv6_dns_server3: <string>
          # ipv6_end_ip: <string>
          # ipv6_exclude_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          # ipv6_name: <list or string>
          # ipv6_prefix: <integer>
          # ipv6_split_exclude: <list or string>
          # ipv6_split_include: <list or string>
          # ipv6_start_ip: <string>
          # keepalive: <integer>
          # keylife: <integer>
          # kms: <list or string>
          # link_cost: <integer>
          # local_gw: <string>
          # local_gw6: <string>
          # localid: <string>
          # localid_type: <value in [auto, fqdn, user-fqdn, ...]>
          # loopback_asymroute: <value in [disable, enable]>
          # mesh_selector_type: <value in [disable, subnet, host]>
          # mode: <value in [main, aggressive]>
          # mode_cfg: <value in [disable, enable]>
          # mode_cfg_allow_client_selector: <value in [disable, enable]>
          # monitor: <list or string>
          # monitor_hold_down_delay: <integer>
          # monitor_hold_down_time: <string>
          # monitor_hold_down_type: <value in [immediate, delay, time]>
          # monitor_hold_down_weekday: <value in [sunday, monday, tuesday, ...]>
          # monitor_min: <integer>
          # nattraversal: <value in [disable, enable, forced]>
          # negotiate_timeout: <integer>
          # net_device: <value in [disable, enable]>
          # network_id: <integer>
          # network_overlay: <value in [disable, enable]>
          # npu_offload: <value in [disable, enable]>
          # packet_redistribution: <value in [disable, enable]>
          # passive_mode: <value in [disable, enable]>
          # peer: <list or string>
          # peergrp: <list or string>
          # peerid: <string>
          # peertype: <value in [any, one, dialup, ...]>
          # ppk: <value in [disable, allow, require]>
          # ppk_identity: <string>
          # ppk_secret: <list or string>
          # priority: <integer>
          # proposal: <value in [des-md5, des-sha1, 3des-md5, ...]>
          # psksecret: <list or string>
          # psksecret_remote: <list or string>
          # qkd: <value in [disable, allow, require]>
          # qkd_profile: <list or string>
          # reauth: <value in [disable, enable]>
          # rekey: <value in [disable, enable]>
          # remote_gw: <string>
          # remote_gw_country: <string>
          # remote_gw_end_ip: <string>
          # remote_gw_match: <value in [any, ipmask, iprange, ...]>
          # remote_gw_start_ip: <string>
          # remote_gw_subnet: <list or string>
          # remote_gw6: <string>
          # remote_gw6_country: <string>
          # remote_gw6_end_ip: <string>
          # remote_gw6_match: <value in [any, iprange, geography, ...]>
          # remote_gw6_start_ip: <string>
          # remote_gw6_subnet: <string>
          # remotegw_ddns: <string>
          # rsa_signature_format: <value in [pkcs1, pss]>
          # rsa_signature_hash_override: <value in [disable, enable]>
          # save_password: <value in [disable, enable]>
          # send_cert_chain: <value in [disable, enable]>
          # signature_hash_alg:
          #   - "sha1"
          #   - "sha2-256"
          #   - "sha2-384"
          #   - "sha2-512"
          # split_include_service: <list or string>
          # suite_b: <value in [disable, suite-b-gcm-128, suite-b-gcm-256]>
          # transit_gateway: <value in [disable, enable]>
          # transport: <value in [udp, tcp, udp-fallback-tcp, ...]>
          # type: <value in [static, dynamic, ddns]>
          # unity_support: <value in [disable, enable]>
          # usrgrp: <list or string>
          # vni: <integer>
          # wizard_type: <value in [custom, dialup-forticlient, dialup-ios, ...]>
          # xauthtype: <value in [disable, client, pap, ...]>
          # forticlient_enforcement: <value in [disable, enable]>
          # tunnel_search: <value in [selectors, nexthop]>
          # addke1:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke2:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke3:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke4:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke5:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke6:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke7:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # auto_transport_threshold: <integer>
          # ipv6_auto_linklocal: <value in [disable, enable]>
          # remote_gw_ztna_tags: <list or string>
          # shared_idle_timeout: <value in [disable, enable]>
          # auto_discovery_dialup_placeholder: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_ipsec_phase1interface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'acct-verify': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-gw-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aggregate-member': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aggregate-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'assign-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'assign-ip-from': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['range', 'usrgrp', 'dhcp', 'name'], 'type': 'str'},
                'authmethod': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['psk', 'rsa-signature', 'signature'], 'type': 'str'},
                'authmethod-remote': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['psk', 'signature'], 'type': 'str'},
                'authpasswd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'authusr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'authusrgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'auto-discovery-crossover': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                'auto-discovery-forwarder': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-offer-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-discovery-psk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-receiver': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-sender': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-shortcuts': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['independent', 'dependent'], 'type': 'str'},
                'auto-negotiate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'azure-ad-autoconnect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'backup-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'banner': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cert-id-validation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-peer-username-strip': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-peer-username-validation': {'v_range': [['7.4.3', '']], 'choices': ['othername', 'rfc822name', 'cn', 'none'], 'type': 'str'},
                'cert-trust-store': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['local', 'ems'], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'childless-ike': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-auto-negotiate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-keep-alive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-resume': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-resume-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'default-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'default-gw-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dev-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dev-id-notification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-ra-giaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dhcp6-ra-linkaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dhgrp': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31', '32'],
                    'elements': 'str'
                },
                'digital-signature-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'distance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dns-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'manual'], 'type': 'str'},
                'domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dpd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'on-idle', 'on-demand'], 'type': 'str'},
                'dpd-retrycount': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dpd-retryinterval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'eap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-cert-auth': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-exclude-peergrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'eap-identity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['use-id-payload', 'send-request'], 'type': 'str'},
                'ems-sn-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['use-global', 'enable', 'disable'], 'type': 'str'},
                'encap-local-gw4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encap-local-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encap-remote-gw4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encap-remote-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encapsulation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'gre', 'vxlan', 'vpn-id-ipip'], 'type': 'str'},
                'encapsulation-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ike', 'ipv4', 'ipv6'], 'type': 'str'},
                'enforce-unique-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'keep-new', 'keep-old'], 'type': 'str'},
                'esn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'require', 'allow'], 'type': 'str'},
                'exchange-fgt-device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exchange-interface-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exchange-ip-addr4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'exchange-ip-addr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fallback-tcp-threshold': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'fec-base': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fec-codec': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['rs', 'xor'], 'type': 'str'},
                'fec-egress': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fec-health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fec-ingress': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fec-mapping-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fec-receive-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fec-redundant': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fec-send-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fgsp-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortinet-esp': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fragmentation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fragmentation-mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'group-authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-authentication-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ha-sync-esp-seqno': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'idle-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'idle-timeoutinterval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ike-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2'], 'type': 'str'},
                'inbound-dscp-copy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'include-local-lan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internal-domain-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-delay-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip-fragmentation': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['pre-encapsulation', 'post-encapsulation'],
                    'type': 'str'
                },
                'ip-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['4', '6'], 'type': 'str'},
                'ipsec-tunnel-slot': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'master', 'auto', 'FPC1', 'FPC2', 'FPC3', 'FPC4', 'FPC5', 'FPC6', 'FPC7', 'FPC8', 'FPC9', 'FPC10', 'FPM3', 'FPM4', 'FPM5',
                        'FPM6', 'FPM7', 'FPM8', 'FPM9', 'FPM10', 'FPM11', 'FPM12'
                    ],
                    'type': 'str'
                },
                'ipv4-dns-server1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-dns-server2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-dns-server3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-exclude-range': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ipv4-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv4-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-split-exclude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv4-split-include': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv4-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-wins-server1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv4-wins-server2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-dns-server1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-dns-server2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-dns-server3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-exclude-range': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ipv6-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ipv6-split-exclude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-split-include': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'keepalive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'keylife': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'kms': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'link-cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'local-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'local-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'localid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'localid-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['auto', 'fqdn', 'user-fqdn', 'keyid', 'address', 'asn1dn'],
                    'type': 'str'
                },
                'loopback-asymroute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mesh-selector-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'subnet', 'host'], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['main', 'aggressive'], 'type': 'str'},
                'mode-cfg': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mode-cfg-allow-client-selector': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'monitor-hold-down-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'monitor-hold-down-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'monitor-hold-down-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['immediate', 'delay', 'time'], 'type': 'str'},
                'monitor-hold-down-weekday': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'everyday'],
                    'type': 'str'
                },
                'monitor-min': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'nattraversal': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'forced'], 'type': 'str'},
                'negotiate-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'net-device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'network-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'network-overlay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'npu-offload': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'packet-redistribution': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'passive-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'peer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'peergrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'peerid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'peertype': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['any', 'one', 'dialup', 'peer', 'peergrp'], 'type': 'str'},
                'ppk': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'allow', 'require'], 'type': 'str'},
                'ppk-identity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ppk-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'proposal': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'des-md5', 'des-sha1', '3des-md5', '3des-sha1', 'aes128-md5', 'aes128-sha1', 'aes192-md5', 'aes192-sha1', 'aes256-md5',
                        'aes256-sha1', 'des-sha256', '3des-sha256', 'aes128-sha256', 'aes192-sha256', 'aes256-sha256', 'des-sha384', 'des-sha512',
                        '3des-sha384', '3des-sha512', 'aes128-sha384', 'aes128-sha512', 'aes192-sha384', 'aes192-sha512', 'aes256-sha384',
                        'aes256-sha512', 'aria128-md5', 'aria128-sha1', 'aria128-sha256', 'aria128-sha384', 'aria128-sha512', 'aria192-md5',
                        'aria192-sha1', 'aria192-sha256', 'aria192-sha384', 'aria192-sha512', 'aria256-md5', 'aria256-sha1', 'aria256-sha256',
                        'aria256-sha384', 'aria256-sha512', 'seed-md5', 'seed-sha1', 'seed-sha256', 'seed-sha384', 'seed-sha512', 'aes128gcm-prfsha1',
                        'aes128gcm-prfsha256', 'aes128gcm-prfsha384', 'aes128gcm-prfsha512', 'aes256gcm-prfsha1', 'aes256gcm-prfsha256',
                        'aes256gcm-prfsha384', 'aes256gcm-prfsha512', 'chacha20poly1305-prfsha1', 'chacha20poly1305-prfsha256',
                        'chacha20poly1305-prfsha384', 'chacha20poly1305-prfsha512'
                    ],
                    'type': 'str'
                },
                'psksecret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'psksecret-remote': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'qkd': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'allow', 'require'], 'type': 'str'},
                'qkd-profile': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'reauth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rekey': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remote-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw-country': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw-match': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['any', 'ipmask', 'iprange', 'geography', 'ztna'],
                    'type': 'str'
                },
                'remote-gw-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remote-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6-country': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6-match': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['any', 'iprange', 'geography', 'ipprefix'],
                    'type': 'str'
                },
                'remote-gw6-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remotegw-ddns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'rsa-signature-format': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['pkcs1', 'pss'], 'type': 'str'},
                'rsa-signature-hash-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'save-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-cert-chain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'signature-hash-alg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['sha1', 'sha2-256', 'sha2-384', 'sha2-512'],
                    'elements': 'str'
                },
                'split-include-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'suite-b': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'suite-b-gcm-128', 'suite-b-gcm-256'], 'type': 'str'},
                'transit-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transport': {'v_range': [['7.4.3', '']], 'choices': ['udp', 'tcp', 'udp-fallback-tcp', 'auto'], 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['static', 'dynamic', 'ddns'], 'type': 'str'},
                'unity-support': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'usrgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vni': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wizard-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'custom', 'dialup-forticlient', 'dialup-ios', 'dialup-android', 'dialup-cisco', 'static-fortigate', 'static-cisco',
                        'dialup-windows', 'dialup-fortigate', 'dialup-cisco-fw', 'simplified-static-fortigate', 'hub-fortigate-auto-discovery',
                        'spoke-fortigate-auto-discovery', 'static-fortiproxy', 'dialup-fortiproxy', 'simplified-static-fortiproxy',
                        'hub-fortiproxy-auto-discovery', 'spoke-fortiproxy-auto-discovery', 'fabric-overlay-orchestrator'
                    ],
                    'type': 'str'
                },
                'xauthtype': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'client', 'pap', 'chap', 'auto'], 'type': 'str'},
                'forticlient-enforcement': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-search': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['selectors', 'nexthop'], 'type': 'str'},
                'addke1': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke2': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke3': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke4': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke5': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke6': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke7': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'auto-transport-threshold': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ipv6-auto-linklocal': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remote-gw-ztna-tags': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'shared-idle-timeout': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-dialup-placeholder': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_phase1interface'),
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
