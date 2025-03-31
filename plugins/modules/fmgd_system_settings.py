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
module: fmgd_system_settings
short_description: Configure VDOM settings.
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    system_settings:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allow_linkdown_path:
                aliases: ['allow-linkdown-path']
                type: str
                description: Enable/disable link down path.
                choices:
                    - 'disable'
                    - 'enable'
            allow_subnet_overlap:
                aliases: ['allow-subnet-overlap']
                type: str
                description: Enable/disable allowing interface subnets to use overlapping IP addresses.
                choices:
                    - 'disable'
                    - 'enable'
            application_bandwidth_tracking:
                aliases: ['application-bandwidth-tracking']
                type: str
                description: Enable/disable application bandwidth tracking.
                choices:
                    - 'disable'
                    - 'enable'
            asymroute:
                type: str
                description: Enable/disable IPv4 asymmetric routing.
                choices:
                    - 'disable'
                    - 'enable'
            asymroute_icmp:
                aliases: ['asymroute-icmp']
                type: str
                description: Enable/disable ICMP asymmetric routing.
                choices:
                    - 'disable'
                    - 'enable'
            asymroute6:
                type: str
                description: Enable/disable asymmetric IPv6 routing.
                choices:
                    - 'disable'
                    - 'enable'
            asymroute6_icmp:
                aliases: ['asymroute6-icmp']
                type: str
                description: Enable/disable asymmetric ICMPv6 routing.
                choices:
                    - 'disable'
                    - 'enable'
            auxiliary_session:
                aliases: ['auxiliary-session']
                type: str
                description: Enable/disable auxiliary session.
                choices:
                    - 'disable'
                    - 'enable'
            bfd:
                type: str
                description: Enable/disable Bi-directional Forwarding Detection
                choices:
                    - 'disable'
                    - 'enable'
            bfd_desired_min_tx:
                aliases: ['bfd-desired-min-tx']
                type: int
                description: BFD desired minimal transmit interval
            bfd_detect_mult:
                aliases: ['bfd-detect-mult']
                type: int
                description: BFD detection multiplier
            bfd_dont_enforce_src_port:
                aliases: ['bfd-dont-enforce-src-port']
                type: str
                description: Enable to not enforce verifying the source port of BFD Packets.
                choices:
                    - 'disable'
                    - 'enable'
            bfd_required_min_rx:
                aliases: ['bfd-required-min-rx']
                type: int
                description: BFD required minimal receive interval
            block_land_attack:
                aliases: ['block-land-attack']
                type: str
                description: Enable/disable blocking of land attacks.
                choices:
                    - 'disable'
                    - 'enable'
            central_nat:
                aliases: ['central-nat']
                type: str
                description: Enable/disable central NAT.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: VDOM comments.
            default_app_port_as_service:
                aliases: ['default-app-port-as-service']
                type: str
                description: Enable/disable policy service enforcement based on application default ports.
                choices:
                    - 'disable'
                    - 'enable'
            default_policy_expiry_days:
                aliases: ['default-policy-expiry-days']
                type: int
                description: Default policy expiry in days
            default_voip_alg_mode:
                aliases: ['default-voip-alg-mode']
                type: str
                description: Configure how the FortiGate handles VoIP traffic when a policy that accepts the traffic doesnt include a VoIP profile.
                choices:
                    - 'proxy-based'
                    - 'kernel-helper-based'
            deny_tcp_with_icmp:
                aliases: ['deny-tcp-with-icmp']
                type: str
                description: Enable/disable denying TCP by sending an ICMP communication prohibited packet.
                choices:
                    - 'disable'
                    - 'enable'
            detect_unknown_esp:
                aliases: ['detect-unknown-esp']
                type: str
                description: Enable/disable detection of unknown ESP packets
                choices:
                    - 'disable'
                    - 'enable'
            device:
                type: list
                elements: str
                description: Interface to use for management access for NAT mode.
            dhcp_proxy:
                aliases: ['dhcp-proxy']
                type: str
                description: Enable/disable the DHCP Proxy.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_proxy_interface:
                aliases: ['dhcp-proxy-interface']
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            dhcp_proxy_interface_select_method:
                aliases: ['dhcp-proxy-interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            dhcp_server_ip:
                aliases: ['dhcp-server-ip']
                type: list
                elements: str
                description: DHCP Server IPv4 address.
            dhcp6_server_ip:
                aliases: ['dhcp6-server-ip']
                type: list
                elements: str
                description: DHCPv6 server IPv6 address.
            discovered_device_timeout:
                aliases: ['discovered-device-timeout']
                type: int
                description: Timeout for discovered devices
            dp_load_distribution_method:
                aliases: ['dp-load-distribution-method']
                type: str
                description: Per VDOM DP load distribution method.
                choices:
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
                    - 'src-ip-sport'
                    - 'dst-ip-dport'
                    - 'src-dst-ip-sport-dport'
                    - 'to-master'
                    - 'derived'
                    - 'to-primary'
            dyn_addr_session_check:
                aliases: ['dyn-addr-session-check']
                type: str
                description: Enable/disable dirty session check caused by dynamic address updates.
                choices:
                    - 'disable'
                    - 'enable'
            ecmp_max_paths:
                aliases: ['ecmp-max-paths']
                type: int
                description: Maximum number of Equal Cost Multi-Path
            email_portal_check_dns:
                aliases: ['email-portal-check-dns']
                type: str
                description: Enable/disable using DNS to validate email addresses collected by a captive portal.
                choices:
                    - 'disable'
                    - 'enable'
            ext_resource_session_check:
                aliases: ['ext-resource-session-check']
                type: str
                description: Enable/disable dirty session check caused by external resource updates.
                choices:
                    - 'disable'
                    - 'enable'
            firewall_session_dirty:
                aliases: ['firewall-session-dirty']
                type: str
                description: Select how to manage sessions affected by firewall policy configuration changes.
                choices:
                    - 'check-all'
                    - 'check-new'
                    - 'check-policy-option'
            fqdn_session_check:
                aliases: ['fqdn-session-check']
                type: str
                description: Enable/disable dirty session check caused by FQDN updates.
                choices:
                    - 'disable'
                    - 'enable'
            fw_session_hairpin:
                aliases: ['fw-session-hairpin']
                type: str
                description: Enable/disable checking for a matching policy each time hairpin traffic goes through the FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            gateway:
                type: str
                description: Transparent mode IPv4 default gateway IP address.
            gateway6:
                type: str
                description: Transparent mode IPv6 default gateway IP address.
            gtp_asym_fgsp:
                aliases: ['gtp-asym-fgsp']
                type: str
                description: Enable/disable GTP asymmetric traffic handling on FGSP.
                choices:
                    - 'disable'
                    - 'enable'
            gtp_monitor_mode:
                aliases: ['gtp-monitor-mode']
                type: str
                description: Enable/disable GTP monitor mode
                choices:
                    - 'disable'
                    - 'enable'
            gui_advanced_policy:
                aliases: ['gui-advanced-policy']
                type: str
                description: Enable/disable advanced policy configuration on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_advanced_wireless_features:
                aliases: ['gui-advanced-wireless-features']
                type: str
                description: Enable/disable advanced wireless features in GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_allow_unnamed_policy:
                aliases: ['gui-allow-unnamed-policy']
                type: str
                description: Enable/disable the requirement for policy naming on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_antivirus:
                aliases: ['gui-antivirus']
                type: str
                description: Enable/disable AntiVirus on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_ap_profile:
                aliases: ['gui-ap-profile']
                type: str
                description: Enable/disable FortiAP profiles on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_application_control:
                aliases: ['gui-application-control']
                type: str
                description: Enable/disable application control on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_casb:
                aliases: ['gui-casb']
                type: str
                description: Enable/disable Inline-CASB on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_default_policy_columns:
                aliases: ['gui-default-policy-columns']
                type: list
                elements: str
                description: Default columns to display for policy lists on GUI.
            gui_dhcp_advanced:
                aliases: ['gui-dhcp-advanced']
                type: str
                description: Enable/disable advanced DHCP options on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dlp_profile:
                aliases: ['gui-dlp-profile']
                type: str
                description: Enable/disable Data Loss Prevention on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dns_database:
                aliases: ['gui-dns-database']
                type: str
                description: Enable/disable DNS database settings on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dnsfilter:
                aliases: ['gui-dnsfilter']
                type: str
                description: Enable/disable DNS Filtering on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dos_policy:
                aliases: ['gui-dos-policy']
                type: str
                description: Enable/disable DoS policies on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dynamic_device_os_id:
                aliases: ['gui-dynamic-device-os-id']
                type: str
                description: Enable/disable Create dynamic addresses to manage known devices.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dynamic_routing:
                aliases: ['gui-dynamic-routing']
                type: str
                description: Enable/disable dynamic routing on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_email_collection:
                aliases: ['gui-email-collection']
                type: str
                description: Enable/disable email collection on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_enforce_change_summary:
                aliases: ['gui-enforce-change-summary']
                type: str
                description: Enforce change summaries for select tables in the GUI.
                choices:
                    - 'disable'
                    - 'require'
                    - 'optional'
            gui_explicit_proxy:
                aliases: ['gui-explicit-proxy']
                type: str
                description: Enable/disable the explicit proxy on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_file_filter:
                aliases: ['gui-file-filter']
                type: str
                description: Enable/disable File-filter on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_fortiap_split_tunneling:
                aliases: ['gui-fortiap-split-tunneling']
                type: str
                description: Enable/disable FortiAP split tunneling on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_fortiextender_controller:
                aliases: ['gui-fortiextender-controller']
                type: str
                description: Enable/disable FortiExtender on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_icap:
                aliases: ['gui-icap']
                type: str
                description: Enable/disable ICAP on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_implicit_policy:
                aliases: ['gui-implicit-policy']
                type: str
                description: Enable/disable implicit firewall policies on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_ips:
                aliases: ['gui-ips']
                type: str
                description: Enable/disable IPS on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_load_balance:
                aliases: ['gui-load-balance']
                type: str
                description: Enable/disable server load balancing on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_local_in_policy:
                aliases: ['gui-local-in-policy']
                type: str
                description: Enable/disable Local-In policies on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_multicast_policy:
                aliases: ['gui-multicast-policy']
                type: str
                description: Enable/disable multicast firewall policies on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_multiple_interface_policy:
                aliases: ['gui-multiple-interface-policy']
                type: str
                description: Enable/disable adding multiple interfaces to a policy on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_object_colors:
                aliases: ['gui-object-colors']
                type: str
                description: Enable/disable object colors on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_ot:
                aliases: ['gui-ot']
                type: str
                description: Enable/disable Operational technology features on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_policy_based_ipsec:
                aliases: ['gui-policy-based-ipsec']
                type: str
                description: Enable/disable policy-based IPsec VPN on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_policy_disclaimer:
                aliases: ['gui-policy-disclaimer']
                type: str
                description: Enable/disable policy disclaimer on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_proxy_inspection:
                aliases: ['gui-proxy-inspection']
                type: str
                description: Enable/disable the proxy features on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_route_tag_address_creation:
                aliases: ['gui-route-tag-address-creation']
                type: str
                description: Enable/disable route-tag addresses on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_security_profile_group:
                aliases: ['gui-security-profile-group']
                type: str
                description: Enable/disable Security Profile Groups on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_spamfilter:
                aliases: ['gui-spamfilter']
                type: str
                description: Enable/disable Antispam on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_sslvpn:
                aliases: ['gui-sslvpn']
                type: str
                description: Enable/disable SSL-VPN settings pages on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_sslvpn_personal_bookmarks:
                aliases: ['gui-sslvpn-personal-bookmarks']
                type: str
                description: Enable/disable SSL-VPN personal bookmark management on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_sslvpn_realms:
                aliases: ['gui-sslvpn-realms']
                type: str
                description: Enable/disable SSL-VPN realms on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_switch_controller:
                aliases: ['gui-switch-controller']
                type: str
                description: Enable/disable the switch controller on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_threat_weight:
                aliases: ['gui-threat-weight']
                type: str
                description: Enable/disable threat weight on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_traffic_shaping:
                aliases: ['gui-traffic-shaping']
                type: str
                description: Enable/disable traffic shaping on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_videofilter:
                aliases: ['gui-videofilter']
                type: str
                description: Enable/disable Video filtering on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_virtual_patch_profile:
                aliases: ['gui-virtual-patch-profile']
                type: str
                description: Enable/disable Virtual Patching on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_voip_profile:
                aliases: ['gui-voip-profile']
                type: str
                description: Enable/disable VoIP profiles on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_vpn:
                aliases: ['gui-vpn']
                type: str
                description: Enable/disable IPsec VPN settings pages on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_waf_profile:
                aliases: ['gui-waf-profile']
                type: str
                description: Enable/disable Web Application Firewall on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_wan_load_balancing:
                aliases: ['gui-wan-load-balancing']
                type: str
                description: Enable/disable SD-WAN on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_wanopt_cache:
                aliases: ['gui-wanopt-cache']
                type: str
                description: Enable/disable WAN Optimization and Web Caching on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_webfilter:
                aliases: ['gui-webfilter']
                type: str
                description: Enable/disable Web filtering on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_webfilter_advanced:
                aliases: ['gui-webfilter-advanced']
                type: str
                description: Enable/disable advanced web filtering on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_wireless_controller:
                aliases: ['gui-wireless-controller']
                type: str
                description: Enable/disable the wireless controller on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_ztna:
                aliases: ['gui-ztna']
                type: str
                description: Enable/disable Zero Trust Network Access features on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            h323_direct_model:
                aliases: ['h323-direct-model']
                type: str
                description: Enable/disable H323 direct model.
                choices:
                    - 'disable'
                    - 'enable'
            http_external_dest:
                aliases: ['http-external-dest']
                type: str
                description: Offload HTTP traffic to FortiWeb or FortiCache.
                choices:
                    - 'fortiweb'
                    - 'forticache'
            hyperscale_default_policy_action:
                aliases: ['hyperscale-default-policy-action']
                type: str
                description: Hyperscale default policy action.
                choices:
                    - 'drop-on-hardware'
                    - 'forward-to-host'
            ike_dn_format:
                aliases: ['ike-dn-format']
                type: str
                description: Configure IKE ASN.
                choices:
                    - 'with-space'
                    - 'no-space'
            ike_policy_route:
                aliases: ['ike-policy-route']
                type: str
                description: Enable/disable IKE Policy Based Routing
                choices:
                    - 'disable'
                    - 'enable'
            ike_port:
                aliases: ['ike-port']
                type: int
                description: UDP port for IKE/IPsec traffic
            ike_quick_crash_detect:
                aliases: ['ike-quick-crash-detect']
                type: str
                description: Enable/disable IKE quick crash detection
                choices:
                    - 'disable'
                    - 'enable'
            ike_session_resume:
                aliases: ['ike-session-resume']
                type: str
                description: Enable/disable IKEv2 session resumption
                choices:
                    - 'disable'
                    - 'enable'
            ike_tcp_port:
                aliases: ['ike-tcp-port']
                type: int
                description: TCP port for IKE/IPsec traffic
            internet_service_app_ctrl_size:
                aliases: ['internet-service-app-ctrl-size']
                type: int
                description: Maximum number of tuple entries
            internet_service_database_cache:
                aliases: ['internet-service-database-cache']
                type: str
                description: Enable/disable Internet Service database caching.
                choices:
                    - 'disable'
                    - 'enable'
            ip:
                type: list
                elements: str
                description: IP address and netmask.
            ip6:
                type: str
                description: IPv6 address prefix for NAT mode.
            lan_extension_controller_addr:
                aliases: ['lan-extension-controller-addr']
                type: str
                description: Controller IP address or FQDN to connect.
            link_down_access:
                aliases: ['link-down-access']
                type: str
                description: Enable/disable link down access traffic.
                choices:
                    - 'disable'
                    - 'enable'
            lldp_reception:
                aliases: ['lldp-reception']
                type: str
                description: Enable/disable Link Layer Discovery Protocol
                choices:
                    - 'disable'
                    - 'enable'
                    - 'global'
            lldp_transmission:
                aliases: ['lldp-transmission']
                type: str
                description: Enable/disable Link Layer Discovery Protocol
                choices:
                    - 'enable'
                    - 'disable'
                    - 'global'
            location_id:
                aliases: ['location-id']
                type: str
                description: Local location ID in the form of an IPv4 address.
            mac_ttl:
                aliases: ['mac-ttl']
                type: int
                description: Duration of MAC addresses in Transparent mode
            manageip:
                type: list
                elements: str
                description: Transparent mode IPv4 management IP address and netmask.
            manageip6:
                type: str
                description: Transparent mode IPv6 management IP address and netmask.
            multicast_forward:
                aliases: ['multicast-forward']
                type: str
                description: Enable/disable multicast forwarding.
                choices:
                    - 'disable'
                    - 'enable'
            multicast_skip_policy:
                aliases: ['multicast-skip-policy']
                type: str
                description: Enable/disable allowing multicast traffic through the FortiGate without a policy check.
                choices:
                    - 'disable'
                    - 'enable'
            multicast_ttl_notchange:
                aliases: ['multicast-ttl-notchange']
                type: str
                description: Enable/disable preventing the FortiGate from changing the TTL for forwarded multicast packets.
                choices:
                    - 'disable'
                    - 'enable'
            nat46_force_ipv4_packet_forwarding:
                aliases: ['nat46-force-ipv4-packet-forwarding']
                type: str
                description: Enable/disable mandatory IPv4 packet forwarding in NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat46_generate_ipv6_fragment_header:
                aliases: ['nat46-generate-ipv6-fragment-header']
                type: str
                description: Enable/disable NAT46 IPv6 fragment header generation.
                choices:
                    - 'disable'
                    - 'enable'
            nat64_force_ipv6_packet_forwarding:
                aliases: ['nat64-force-ipv6-packet-forwarding']
                type: str
                description: Enable/disable mandatory IPv6 packet forwarding in NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            ngfw_mode:
                aliases: ['ngfw-mode']
                type: str
                description: Next Generation Firewall
                choices:
                    - 'profile-based'
                    - 'policy-based'
            npu_group_id:
                aliases: ['npu-group-id']
                type: int
                description: Npu-group-index.
            opmode:
                type: str
                description: Firewall operation mode
                choices:
                    - 'nat'
                    - 'transparent'
            pfcp_monitor_mode:
                aliases: ['pfcp-monitor-mode']
                type: str
                description: Enable/disable PFCP monitor mode
                choices:
                    - 'disable'
                    - 'enable'
            policy_offload_level:
                aliases: ['policy-offload-level']
                type: str
                description: Configure firewall policy offload level.
                choices:
                    - 'disable'
                    - 'default'
                    - 'dos-offload'
                    - 'full-offload'
            prp_trailer_action:
                aliases: ['prp-trailer-action']
                type: str
                description: Enable/disable action to take on PRP trailer.
                choices:
                    - 'disable'
                    - 'enable'
            sccp_port:
                aliases: ['sccp-port']
                type: int
                description: TCP port the SCCP proxy monitors for SCCP traffic
            sctp_session_without_init:
                aliases: ['sctp-session-without-init']
                type: str
                description: Enable/disable SCTP session creation without SCTP INIT.
                choices:
                    - 'disable'
                    - 'enable'
            ses_denied_traffic:
                aliases: ['ses-denied-traffic']
                type: str
                description: Enable/disable including denied session in the session table.
                choices:
                    - 'disable'
                    - 'enable'
            session_insert_trial:
                aliases: ['session-insert-trial']
                type: str
                description: Trial session insert.
                choices:
                    - 'disable'
                    - 'enable'
            sip_expectation:
                aliases: ['sip-expectation']
                type: str
                description: Enable/disable the SIP kernel session helper to create an expectation for port 5060.
                choices:
                    - 'disable'
                    - 'enable'
            sip_nat_trace:
                aliases: ['sip-nat-trace']
                type: str
                description: Enable/disable recording the original SIP source IP address when NAT is used.
                choices:
                    - 'disable'
                    - 'enable'
            sip_ssl_port:
                aliases: ['sip-ssl-port']
                type: int
                description: TCP port the SIP proxy monitors for SIP SSL/TLS traffic
            sip_tcp_port:
                aliases: ['sip-tcp-port']
                type: list
                elements: int
                description: TCP port the SIP proxy monitors for SIP traffic
            sip_udp_port:
                aliases: ['sip-udp-port']
                type: list
                elements: int
                description: UDP port the SIP proxy monitors for SIP traffic
            snat_hairpin_traffic:
                aliases: ['snat-hairpin-traffic']
                type: str
                description: Enable/disable source NAT
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable this VDOM.
                choices:
                    - 'disable'
                    - 'enable'
            strict_src_check:
                aliases: ['strict-src-check']
                type: str
                description: Enable/disable strict source verification.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_session_without_syn:
                aliases: ['tcp-session-without-syn']
                type: str
                description: Enable/disable allowing TCP session without SYN flags.
                choices:
                    - 'disable'
                    - 'enable'
            trap_local_session:
                aliases: ['trap-local-session']
                type: str
                description: Enable/disable local-in traffic session traps.
                choices:
                    - 'disable'
                    - 'enable'
            trap_session_flag:
                aliases: ['trap-session-flag']
                type: str
                description: Trap session operation flags.
                choices:
                    - 'udp-both'
                    - 'udp-reply'
                    - 'tcpudp-both'
                    - 'tcpudp-reply'
                    - 'trap-none'
            utf8_spam_tagging:
                aliases: ['utf8-spam-tagging']
                type: str
                description: Enable/disable converting antispam tags to UTF-8 for better non-ASCII character support.
                choices:
                    - 'disable'
                    - 'enable'
            v4_ecmp_mode:
                aliases: ['v4-ecmp-mode']
                type: str
                description: IPv4 Equal-cost multi-path
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
            vdom_type:
                aliases: ['vdom-type']
                type: str
                description: Vdom type
                choices:
                    - 'traffic'
                    - 'admin'
                    - 'lan-extension'
            vpn_stats_log:
                aliases: ['vpn-stats-log']
                type: list
                elements: str
                description: Enable/disable periodic VPN log statistics for one or more types of VPN.
                choices:
                    - 'ipsec'
                    - 'pptp'
                    - 'l2tp'
                    - 'ssl'
            vpn_stats_period:
                aliases: ['vpn-stats-period']
                type: int
                description: Period to send VPN log statistics
            wccp_cache_engine:
                aliases: ['wccp-cache-engine']
                type: str
                description: Enable/disable WCCP cache engine.
                choices:
                    - 'disable'
                    - 'enable'
            gui_endpoint_control_advanced:
                aliases: ['gui-endpoint-control-advanced']
                type: str
                description: Enable/disable advanced endpoint control options on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_endpoint_control:
                aliases: ['gui-endpoint-control']
                type: str
                description: Enable/disable endpoint control on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_local_reports:
                aliases: ['gui-local-reports']
                type: str
                description: Enable/disable local reports on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_nat46_64:
                aliases: ['gui-nat46-64']
                type: str
                description: Enable/disable NAT46 and NAT64 settings on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_dynamic_profile_display:
                aliases: ['gui-dynamic-profile-display']
                type: str
                description: Enable/disable RADIUS Single Sign On
                choices:
                    - 'disable'
                    - 'enable'
            gui_replacement_message_groups:
                aliases: ['gui-replacement-message-groups']
                type: str
                description: Enable/disable replacement message groups on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_domain_ip_reputation:
                aliases: ['gui-domain-ip-reputation']
                type: str
                description: Enable/disable Domain and IP Reputation on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_multiple_utm_profiles:
                aliases: ['gui-multiple-utm-profiles']
                type: str
                description: Enable/disable multiple UTM profiles on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            implicit_allow_dns:
                aliases: ['implicit-allow-dns']
                type: str
                description: Enable/disable implicitly allowing DNS traffic.
                choices:
                    - 'disable'
                    - 'enable'
            gui_per_policy_disclaimer:
                aliases: ['gui-per-policy-disclaimer']
                type: str
                description: Enable/disable policy disclaimer on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            consolidated_firewall_mode:
                aliases: ['consolidated-firewall-mode']
                type: str
                description: Consolidated firewall mode.
                choices:
                    - 'disable'
                    - 'enable'
            motherboard_traffic_forwarding:
                aliases: ['motherboard-traffic-forwarding']
                type: list
                elements: str
                description: Motherboard traffic forwarding.
                choices:
                    - 'icmp'
                    - 'admin'
                    - 'auth'
            gui_gtp:
                aliases: ['gui-gtp']
                type: str
                description: Enable/disable Manage general radio packet service
                choices:
                    - 'disable'
                    - 'enable'
            nonat_eif_key_sel:
                aliases: ['nonat-eif-key-sel']
                type: str
                description: Nonat EIF tuple key selection.
                choices:
                    - 'dip-only'
                    - 'dip-dport'
                    - 'dip-dport-proto'
            ses_denied_multicast_traffic:
                aliases: ['ses-denied-multicast-traffic']
                type: str
                description: Enable/disable including denied multicast session in the session table.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_proxy_vrf_select:
                aliases: ['dhcp-proxy-vrf-select']
                type: int
                description: VRF ID used for connection to server.
            dp_load_distribution_group:
                aliases: ['dp-load-distribution-group']
                type: list
                elements: str
                description: Per VDOM DP load distribution group.
            gui_dlp_advanced:
                aliases: ['gui-dlp-advanced']
                type: str
                description: Enable/disable Show advanced DLP expressions on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_sslvpn_clients:
                aliases: ['gui-sslvpn-clients']
                type: str
                description: Enable/disable SSL-VPN clients on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            intree_ses_best_route:
                aliases: ['intree-ses-best-route']
                type: str
                description: Force the intree session to always use the best route.
                choices:
                    - 'force'
                    - 'disable'
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
    - name: Configure VDOM settings.
      fortinet.fmgdevice.fmgd_system_settings:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        system_settings:
          # allow_linkdown_path: <value in [disable, enable]>
          # allow_subnet_overlap: <value in [disable, enable]>
          # application_bandwidth_tracking: <value in [disable, enable]>
          # asymroute: <value in [disable, enable]>
          # asymroute_icmp: <value in [disable, enable]>
          # asymroute6: <value in [disable, enable]>
          # asymroute6_icmp: <value in [disable, enable]>
          # auxiliary_session: <value in [disable, enable]>
          # bfd: <value in [disable, enable]>
          # bfd_desired_min_tx: <integer>
          # bfd_detect_mult: <integer>
          # bfd_dont_enforce_src_port: <value in [disable, enable]>
          # bfd_required_min_rx: <integer>
          # block_land_attack: <value in [disable, enable]>
          # central_nat: <value in [disable, enable]>
          # comments: <string>
          # default_app_port_as_service: <value in [disable, enable]>
          # default_policy_expiry_days: <integer>
          # default_voip_alg_mode: <value in [proxy-based, kernel-helper-based]>
          # deny_tcp_with_icmp: <value in [disable, enable]>
          # detect_unknown_esp: <value in [disable, enable]>
          # device: <list or string>
          # dhcp_proxy: <value in [disable, enable]>
          # dhcp_proxy_interface: <list or string>
          # dhcp_proxy_interface_select_method: <value in [auto, sdwan, specify]>
          # dhcp_server_ip: <list or string>
          # dhcp6_server_ip: <list or string>
          # discovered_device_timeout: <integer>
          # dp_load_distribution_method: <value in [src-ip, dst-ip, src-dst-ip, ...]>
          # dyn_addr_session_check: <value in [disable, enable]>
          # ecmp_max_paths: <integer>
          # email_portal_check_dns: <value in [disable, enable]>
          # ext_resource_session_check: <value in [disable, enable]>
          # firewall_session_dirty: <value in [check-all, check-new, check-policy-option]>
          # fqdn_session_check: <value in [disable, enable]>
          # fw_session_hairpin: <value in [disable, enable]>
          # gateway: <string>
          # gateway6: <string>
          # gtp_asym_fgsp: <value in [disable, enable]>
          # gtp_monitor_mode: <value in [disable, enable]>
          # gui_advanced_policy: <value in [disable, enable]>
          # gui_advanced_wireless_features: <value in [disable, enable]>
          # gui_allow_unnamed_policy: <value in [disable, enable]>
          # gui_antivirus: <value in [disable, enable]>
          # gui_ap_profile: <value in [disable, enable]>
          # gui_application_control: <value in [disable, enable]>
          # gui_casb: <value in [disable, enable]>
          # gui_default_policy_columns: <list or string>
          # gui_dhcp_advanced: <value in [disable, enable]>
          # gui_dlp_profile: <value in [disable, enable]>
          # gui_dns_database: <value in [disable, enable]>
          # gui_dnsfilter: <value in [disable, enable]>
          # gui_dos_policy: <value in [disable, enable]>
          # gui_dynamic_device_os_id: <value in [disable, enable]>
          # gui_dynamic_routing: <value in [disable, enable]>
          # gui_email_collection: <value in [disable, enable]>
          # gui_enforce_change_summary: <value in [disable, require, optional]>
          # gui_explicit_proxy: <value in [disable, enable]>
          # gui_file_filter: <value in [disable, enable]>
          # gui_fortiap_split_tunneling: <value in [disable, enable]>
          # gui_fortiextender_controller: <value in [disable, enable]>
          # gui_icap: <value in [disable, enable]>
          # gui_implicit_policy: <value in [disable, enable]>
          # gui_ips: <value in [disable, enable]>
          # gui_load_balance: <value in [disable, enable]>
          # gui_local_in_policy: <value in [disable, enable]>
          # gui_multicast_policy: <value in [disable, enable]>
          # gui_multiple_interface_policy: <value in [disable, enable]>
          # gui_object_colors: <value in [disable, enable]>
          # gui_ot: <value in [disable, enable]>
          # gui_policy_based_ipsec: <value in [disable, enable]>
          # gui_policy_disclaimer: <value in [disable, enable]>
          # gui_proxy_inspection: <value in [disable, enable]>
          # gui_route_tag_address_creation: <value in [disable, enable]>
          # gui_security_profile_group: <value in [disable, enable]>
          # gui_spamfilter: <value in [disable, enable]>
          # gui_sslvpn: <value in [disable, enable]>
          # gui_sslvpn_personal_bookmarks: <value in [disable, enable]>
          # gui_sslvpn_realms: <value in [disable, enable]>
          # gui_switch_controller: <value in [disable, enable]>
          # gui_threat_weight: <value in [disable, enable]>
          # gui_traffic_shaping: <value in [disable, enable]>
          # gui_videofilter: <value in [disable, enable]>
          # gui_virtual_patch_profile: <value in [disable, enable]>
          # gui_voip_profile: <value in [disable, enable]>
          # gui_vpn: <value in [disable, enable]>
          # gui_waf_profile: <value in [disable, enable]>
          # gui_wan_load_balancing: <value in [disable, enable]>
          # gui_wanopt_cache: <value in [disable, enable]>
          # gui_webfilter: <value in [disable, enable]>
          # gui_webfilter_advanced: <value in [disable, enable]>
          # gui_wireless_controller: <value in [disable, enable]>
          # gui_ztna: <value in [disable, enable]>
          # h323_direct_model: <value in [disable, enable]>
          # http_external_dest: <value in [fortiweb, forticache]>
          # hyperscale_default_policy_action: <value in [drop-on-hardware, forward-to-host]>
          # ike_dn_format: <value in [with-space, no-space]>
          # ike_policy_route: <value in [disable, enable]>
          # ike_port: <integer>
          # ike_quick_crash_detect: <value in [disable, enable]>
          # ike_session_resume: <value in [disable, enable]>
          # ike_tcp_port: <integer>
          # internet_service_app_ctrl_size: <integer>
          # internet_service_database_cache: <value in [disable, enable]>
          # ip: <list or string>
          # ip6: <string>
          # lan_extension_controller_addr: <string>
          # link_down_access: <value in [disable, enable]>
          # lldp_reception: <value in [disable, enable, global]>
          # lldp_transmission: <value in [enable, disable, global]>
          # location_id: <string>
          # mac_ttl: <integer>
          # manageip: <list or string>
          # manageip6: <string>
          # multicast_forward: <value in [disable, enable]>
          # multicast_skip_policy: <value in [disable, enable]>
          # multicast_ttl_notchange: <value in [disable, enable]>
          # nat46_force_ipv4_packet_forwarding: <value in [disable, enable]>
          # nat46_generate_ipv6_fragment_header: <value in [disable, enable]>
          # nat64_force_ipv6_packet_forwarding: <value in [disable, enable]>
          # ngfw_mode: <value in [profile-based, policy-based]>
          # npu_group_id: <integer>
          # opmode: <value in [nat, transparent]>
          # pfcp_monitor_mode: <value in [disable, enable]>
          # policy_offload_level: <value in [disable, default, dos-offload, ...]>
          # prp_trailer_action: <value in [disable, enable]>
          # sccp_port: <integer>
          # sctp_session_without_init: <value in [disable, enable]>
          # ses_denied_traffic: <value in [disable, enable]>
          # session_insert_trial: <value in [disable, enable]>
          # sip_expectation: <value in [disable, enable]>
          # sip_nat_trace: <value in [disable, enable]>
          # sip_ssl_port: <integer>
          # sip_tcp_port: <list or integer>
          # sip_udp_port: <list or integer>
          # snat_hairpin_traffic: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # strict_src_check: <value in [disable, enable]>
          # tcp_session_without_syn: <value in [disable, enable]>
          # trap_local_session: <value in [disable, enable]>
          # trap_session_flag: <value in [udp-both, udp-reply, tcpudp-both, ...]>
          # utf8_spam_tagging: <value in [disable, enable]>
          # v4_ecmp_mode: <value in [source-ip-based, weight-based, usage-based, ...]>
          # vdom_type: <value in [traffic, admin, lan-extension]>
          # vpn_stats_log:
          #   - "ipsec"
          #   - "pptp"
          #   - "l2tp"
          #   - "ssl"
          # vpn_stats_period: <integer>
          # wccp_cache_engine: <value in [disable, enable]>
          # gui_endpoint_control_advanced: <value in [disable, enable]>
          # gui_endpoint_control: <value in [disable, enable]>
          # gui_local_reports: <value in [disable, enable]>
          # gui_nat46_64: <value in [disable, enable]>
          # gui_dynamic_profile_display: <value in [disable, enable]>
          # gui_replacement_message_groups: <value in [disable, enable]>
          # gui_domain_ip_reputation: <value in [disable, enable]>
          # gui_multiple_utm_profiles: <value in [disable, enable]>
          # implicit_allow_dns: <value in [disable, enable]>
          # gui_per_policy_disclaimer: <value in [disable, enable]>
          # consolidated_firewall_mode: <value in [disable, enable]>
          # motherboard_traffic_forwarding:
          #   - "icmp"
          #   - "admin"
          #   - "auth"
          # gui_gtp: <value in [disable, enable]>
          # nonat_eif_key_sel: <value in [dip-only, dip-dport, dip-dport-proto]>
          # ses_denied_multicast_traffic: <value in [disable, enable]>
          # dhcp_proxy_vrf_select: <integer>
          # dp_load_distribution_group: <list or string>
          # gui_dlp_advanced: <value in [disable, enable]>
          # gui_sslvpn_clients: <value in [disable, enable]>
          # intree_ses_best_route: <value in [force, disable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/settings'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_settings': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'allow-linkdown-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-subnet-overlap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-bandwidth-tracking': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'asymroute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'asymroute-icmp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'asymroute6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'asymroute6-icmp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auxiliary-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bfd-desired-min-tx': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bfd-detect-mult': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bfd-dont-enforce-src-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bfd-required-min-rx': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'block-land-attack': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'central-nat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'default-app-port-as-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-policy-expiry-days': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-voip-alg-mode': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['proxy-based', 'kernel-helper-based'],
                    'type': 'str'
                },
                'deny-tcp-with-icmp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'detect-unknown-esp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp-proxy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-proxy-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp-proxy-interface-select-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'dhcp-server-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp6-server-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'discovered-device-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dp-load-distribution-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'src-ip', 'dst-ip', 'src-dst-ip', 'src-ip-sport', 'dst-ip-dport', 'src-dst-ip-sport-dport', 'to-master', 'derived', 'to-primary'
                    ],
                    'type': 'str'
                },
                'dyn-addr-session-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ecmp-max-paths': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'email-portal-check-dns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-resource-session-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firewall-session-dirty': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['check-all', 'check-new', 'check-policy-option'],
                    'type': 'str'
                },
                'fqdn-session-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fw-session-hairpin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gateway6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gtp-asym-fgsp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gtp-monitor-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-advanced-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-advanced-wireless-features': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-allow-unnamed-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-antivirus': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-ap-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-application-control': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-casb': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-default-policy-columns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'gui-dhcp-advanced': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dlp-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dns-database': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dnsfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dos-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dynamic-device-os-id': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dynamic-routing': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-email-collection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-enforce-change-summary': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'require', 'optional'],
                    'type': 'str'
                },
                'gui-explicit-proxy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-file-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-fortiap-split-tunneling': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-fortiextender-controller': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-icap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-implicit-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-ips': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-local-in-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-multicast-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-multiple-interface-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-object-colors': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-ot': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-policy-based-ipsec': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-policy-disclaimer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-proxy-inspection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-route-tag-address-creation': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-security-profile-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-spamfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-sslvpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-sslvpn-personal-bookmarks': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-sslvpn-realms': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-switch-controller': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-threat-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-traffic-shaping': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-videofilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-virtual-patch-profile': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-voip-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-vpn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-waf-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-wan-load-balancing': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-wanopt-cache': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-webfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-webfilter-advanced': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-wireless-controller': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-ztna': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h323-direct-model': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-external-dest': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['fortiweb', 'forticache'], 'type': 'str'},
                'hyperscale-default-policy-action': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['drop-on-hardware', 'forward-to-host'],
                    'type': 'str'
                },
                'ike-dn-format': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['with-space', 'no-space'], 'type': 'str'},
                'ike-policy-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ike-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ike-quick-crash-detect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ike-session-resume': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ike-tcp-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'internet-service-app-ctrl-size': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'internet-service-database-cache': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'lan-extension-controller-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'link-down-access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lldp-reception': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'global'], 'type': 'str'},
                'lldp-transmission': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['enable', 'disable', 'global'], 'type': 'str'},
                'location-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mac-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'manageip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'manageip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'multicast-forward': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-skip-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-ttl-notchange': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46-force-ipv4-packet-forwarding': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46-generate-ipv6-fragment-header': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64-force-ipv6-packet-forwarding': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ngfw-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                'npu-group-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'opmode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['nat', 'transparent'], 'type': 'str'},
                'pfcp-monitor-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-offload-level': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'default', 'dos-offload', 'full-offload'],
                    'type': 'str'
                },
                'prp-trailer-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sccp-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sctp-session-without-init': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ses-denied-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-insert-trial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sip-expectation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sip-nat-trace': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sip-ssl-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sip-tcp-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'sip-udp-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'snat-hairpin-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strict-src-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-session-without-syn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-local-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-session-flag': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['udp-both', 'udp-reply', 'tcpudp-both', 'tcpudp-reply', 'trap-none'],
                    'type': 'str'
                },
                'utf8-spam-tagging': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'v4-ecmp-mode': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['source-ip-based', 'weight-based', 'usage-based', 'source-dest-ip-based'],
                    'type': 'str'
                },
                'vdom-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['traffic', 'admin', 'lan-extension'], 'type': 'str'},
                'vpn-stats-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['ipsec', 'pptp', 'l2tp', 'ssl'],
                    'elements': 'str'
                },
                'vpn-stats-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wccp-cache-engine': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-endpoint-control-advanced': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-endpoint-control': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-local-reports': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-nat46-64': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-dynamic-profile-display': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-replacement-message-groups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-domain-ip-reputation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-multiple-utm-profiles': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'implicit-allow-dns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-per-policy-disclaimer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'consolidated-firewall-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'motherboard-traffic-forwarding': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['icmp', 'admin', 'auth'],
                    'elements': 'str'
                },
                'gui-gtp': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nonat-eif-key-sel': {'v_range': [['7.6.0', '']], 'choices': ['dip-only', 'dip-dport', 'dip-dport-proto'], 'type': 'str'},
                'ses-denied-multicast-traffic': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-proxy-vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'dp-load-distribution-group': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'gui-dlp-advanced': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-sslvpn-clients': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intree-ses-best-route': {'v_range': [['7.6.2', '']], 'choices': ['force', 'disable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_settings'),
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
