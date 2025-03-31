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
module: fmgd_fact
short_description: Gather fortimanager device facts.
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
        description: Access token of FortiCloud managed API users, this option is available with FortiManager later than 6.4.0.
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
    facts:
        description: Gathering fortimanager facts.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the retrieved fortimanager facts.
                type: str
                choices:
                    - 'alertemail_setting'
                    - 'antivirus_exemptlist'
                    - 'antivirus_heuristic'
                    - 'antivirus_quarantine'
                    - 'antivirus_settings'
                    - 'application_name'
                    - 'application_rulesettings'
                    - 'automation_setting'
                    - 'aws_vpce'
                    - 'azure_vwaningresspublicips'
                    - 'azure_vwanslb'
                    - 'azure_vwanslb_permanentsecurityrules'
                    - 'azure_vwanslb_permanentsecurityrules_rules'
                    - 'azure_vwanslb_temporarysecurityrules'
                    - 'azure_vwanslb_temporarysecurityrules_rules'
                    - 'casb_attributematch'
                    - 'casb_attributematch_attribute'
                    - 'certificate_remote'
                    - 'dlp_exactdatamatch'
                    - 'dlp_exactdatamatch_columns'
                    - 'dlp_fpdocsource'
                    - 'dlp_settings'
                    - 'dpdk_cpus'
                    - 'dpdk_global'
                    - 'emailfilter_fortiguard'
                    - 'endpointcontrol_fctemsoverride'
                    - 'endpointcontrol_settings'
                    - 'ethernetoam_cfm'
                    - 'ethernetoam_cfm_service'
                    - 'extendercontroller_extender'
                    - 'extendercontroller_extender_controllerreport'
                    - 'extendercontroller_extender_modem1'
                    - 'extendercontroller_extender_modem1_autoswitch'
                    - 'extendercontroller_extender_modem2'
                    - 'extendercontroller_extender_modem2_autoswitch'
                    - 'extendercontroller_extender_wanextension'
                    - 'extensioncontroller_extender'
                    - 'extensioncontroller_extender_wanextension'
                    - 'extensioncontroller_extendervap'
                    - 'extensioncontroller_fortigate'
                    - 'extensioncontroller_fortigateprofile'
                    - 'extensioncontroller_fortigateprofile_lanextension'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxysshclientcert_certextension'
                    - 'firewall_authportal'
                    - 'firewall_dnstranslation'
                    - 'firewall_global'
                    - 'firewall_internetserviceappend'
                    - 'firewall_internetservicedefinition'
                    - 'firewall_internetservicedefinition_entry'
                    - 'firewall_internetservicedefinition_entry_portrange'
                    - 'firewall_internetserviceextension'
                    - 'firewall_internetserviceextension_disableentry'
                    - 'firewall_internetserviceextension_disableentry_ip6range'
                    - 'firewall_internetserviceextension_disableentry_iprange'
                    - 'firewall_internetserviceextension_disableentry_portrange'
                    - 'firewall_internetserviceextension_entry'
                    - 'firewall_internetserviceextension_entry_portrange'
                    - 'firewall_ipmacbinding_setting'
                    - 'firewall_ipmacbinding_table'
                    - 'firewall_iptranslation'
                    - 'firewall_ipv6ehfilter'
                    - 'firewall_ondemandsniffer'
                    - 'firewall_pfcp'
                    - 'firewall_policy'
                    - 'firewall_sniffer'
                    - 'firewall_sniffer_anomaly'
                    - 'firewall_ssh_hostkey'
                    - 'firewall_ssh_localkey'
                    - 'firewall_ssh_setting'
                    - 'firewall_ssl_setting'
                    - 'firewall_sslserver'
                    - 'firewall_ttlpolicy'
                    - 'ftpproxy_explicit'
                    - 'gtp_apnshaper'
                    - 'gtp_ieallowlist'
                    - 'gtp_ieallowlist_entries'
                    - 'gtp_rattimeoutprofile'
                    - 'icap_profile'
                    - 'icap_server'
                    - 'icap_servergroup'
                    - 'icap_servergroup_serverlist'
                    - 'ips_decoder'
                    - 'ips_decoder_parameter'
                    - 'ips_global'
                    - 'ips_rule'
                    - 'ips_rulesettings'
                    - 'ips_settings'
                    - 'ips_tlsactiveprobe'
                    - 'loadbalance_flowrule'
                    - 'loadbalance_setting'
                    - 'loadbalance_setting_workers'
                    - 'loadbalance_workergroup'
                    - 'log_azuresecuritycenter2_filter'
                    - 'log_azuresecuritycenter2_filter_freestyle'
                    - 'log_azuresecuritycenter2_setting'
                    - 'log_azuresecuritycenter2_setting_customfieldname'
                    - 'log_azuresecuritycenter_filter'
                    - 'log_azuresecuritycenter_filter_freestyle'
                    - 'log_azuresecuritycenter_setting'
                    - 'log_azuresecuritycenter_setting_customfieldname'
                    - 'log_disk_filter'
                    - 'log_disk_filter_freestyle'
                    - 'log_disk_setting'
                    - 'log_eventfilter'
                    - 'log_fortianalyzer2_filter'
                    - 'log_fortianalyzer2_filter_freestyle'
                    - 'log_fortianalyzer2_overridefilter'
                    - 'log_fortianalyzer2_overridefilter_freestyle'
                    - 'log_fortianalyzer2_overridesetting'
                    - 'log_fortianalyzer2_setting'
                    - 'log_fortianalyzer3_filter'
                    - 'log_fortianalyzer3_filter_freestyle'
                    - 'log_fortianalyzer3_overridefilter'
                    - 'log_fortianalyzer3_overridefilter_freestyle'
                    - 'log_fortianalyzer3_overridesetting'
                    - 'log_fortianalyzer3_setting'
                    - 'log_fortianalyzer_filter'
                    - 'log_fortianalyzer_filter_freestyle'
                    - 'log_fortianalyzer_overridefilter'
                    - 'log_fortianalyzer_overridefilter_freestyle'
                    - 'log_fortianalyzer_overridesetting'
                    - 'log_fortianalyzer_setting'
                    - 'log_fortianalyzercloud_filter'
                    - 'log_fortianalyzercloud_filter_freestyle'
                    - 'log_fortianalyzercloud_overridefilter'
                    - 'log_fortianalyzercloud_overridefilter_freestyle'
                    - 'log_fortianalyzercloud_overridesetting'
                    - 'log_fortianalyzercloud_setting'
                    - 'log_fortiguard_filter'
                    - 'log_fortiguard_filter_freestyle'
                    - 'log_fortiguard_overridefilter'
                    - 'log_fortiguard_overridefilter_freestyle'
                    - 'log_fortiguard_overridesetting'
                    - 'log_fortiguard_setting'
                    - 'log_guidisplay'
                    - 'log_memory_filter'
                    - 'log_memory_filter_freestyle'
                    - 'log_memory_globalsetting'
                    - 'log_memory_setting'
                    - 'log_nulldevice_filter'
                    - 'log_nulldevice_filter_freestyle'
                    - 'log_nulldevice_setting'
                    - 'log_setting'
                    - 'log_slbc_globalsetting'
                    - 'log_syslogd2_filter'
                    - 'log_syslogd2_filter_freestyle'
                    - 'log_syslogd2_overridefilter'
                    - 'log_syslogd2_overridefilter_freestyle'
                    - 'log_syslogd2_overridesetting'
                    - 'log_syslogd2_overridesetting_customfieldname'
                    - 'log_syslogd2_setting'
                    - 'log_syslogd2_setting_customfieldname'
                    - 'log_syslogd3_filter'
                    - 'log_syslogd3_filter_freestyle'
                    - 'log_syslogd3_overridefilter'
                    - 'log_syslogd3_overridefilter_freestyle'
                    - 'log_syslogd3_overridesetting'
                    - 'log_syslogd3_overridesetting_customfieldname'
                    - 'log_syslogd3_setting'
                    - 'log_syslogd3_setting_customfieldname'
                    - 'log_syslogd4_filter'
                    - 'log_syslogd4_filter_freestyle'
                    - 'log_syslogd4_overridefilter'
                    - 'log_syslogd4_overridefilter_freestyle'
                    - 'log_syslogd4_overridesetting'
                    - 'log_syslogd4_overridesetting_customfieldname'
                    - 'log_syslogd4_setting'
                    - 'log_syslogd4_setting_customfieldname'
                    - 'log_syslogd_filter'
                    - 'log_syslogd_filter_freestyle'
                    - 'log_syslogd_overridefilter'
                    - 'log_syslogd_overridefilter_freestyle'
                    - 'log_syslogd_overridesetting'
                    - 'log_syslogd_overridesetting_customfieldname'
                    - 'log_syslogd_setting'
                    - 'log_syslogd_setting_customfieldname'
                    - 'log_tacacsaccounting2_filter'
                    - 'log_tacacsaccounting2_setting'
                    - 'log_tacacsaccounting3_filter'
                    - 'log_tacacsaccounting3_setting'
                    - 'log_tacacsaccounting_filter'
                    - 'log_tacacsaccounting_setting'
                    - 'log_webtrends_filter'
                    - 'log_webtrends_filter_freestyle'
                    - 'log_webtrends_setting'
                    - 'monitoring_np6ipsecengine'
                    - 'monitoring_npuhpe'
                    - 'notification'
                    - 'nsx_profile'
                    - 'nsxt_servicechain'
                    - 'nsxt_servicechain_serviceindex'
                    - 'nsxt_setting'
                    - 'pfcp_messagefilter'
                    - 'report_chart'
                    - 'report_chart_categoryseries'
                    - 'report_chart_column'
                    - 'report_chart_column_mapping'
                    - 'report_chart_drilldowncharts'
                    - 'report_chart_valueseries'
                    - 'report_chart_xseries'
                    - 'report_chart_yseries'
                    - 'report_dataset'
                    - 'report_dataset_field'
                    - 'report_dataset_parameters'
                    - 'report_layout'
                    - 'report_layout_bodyitem'
                    - 'report_layout_bodyitem_list'
                    - 'report_layout_bodyitem_parameters'
                    - 'report_layout_page'
                    - 'report_layout_page_footer'
                    - 'report_layout_page_footer_footeritem'
                    - 'report_layout_page_header'
                    - 'report_layout_page_header_headeritem'
                    - 'report_setting'
                    - 'report_style'
                    - 'report_theme'
                    - 'router_authpath'
                    - 'router_bfd'
                    - 'router_bfd6'
                    - 'router_bfd6_multihoptemplate'
                    - 'router_bfd6_neighbor'
                    - 'router_bfd_multihoptemplate'
                    - 'router_bfd_neighbor'
                    - 'router_bgp'
                    - 'router_bgp_admindistance'
                    - 'router_bgp_aggregateaddress'
                    - 'router_bgp_aggregateaddress6'
                    - 'router_bgp_neighbor'
                    - 'router_bgp_neighbor_conditionaladvertise'
                    - 'router_bgp_neighbor_conditionaladvertise6'
                    - 'router_bgp_neighborgroup'
                    - 'router_bgp_neighborrange'
                    - 'router_bgp_neighborrange6'
                    - 'router_bgp_network'
                    - 'router_bgp_network6'
                    - 'router_bgp_redistribute'
                    - 'router_bgp_redistribute6'
                    - 'router_bgp_vrf'
                    - 'router_bgp_vrf6'
                    - 'router_bgp_vrf6_leaktarget'
                    - 'router_bgp_vrf_leaktarget'
                    - 'router_bgp_vrfleak'
                    - 'router_bgp_vrfleak6'
                    - 'router_bgp_vrfleak6_target'
                    - 'router_bgp_vrfleak_target'
                    - 'router_extcommunitylist'
                    - 'router_extcommunitylist_rule'
                    - 'router_isis'
                    - 'router_isis_isisinterface'
                    - 'router_isis_isisnet'
                    - 'router_isis_redistribute'
                    - 'router_isis_redistribute6'
                    - 'router_isis_summaryaddress'
                    - 'router_isis_summaryaddress6'
                    - 'router_keychain'
                    - 'router_keychain_key'
                    - 'router_multicast'
                    - 'router_multicast6'
                    - 'router_multicast6_interface'
                    - 'router_multicast6_pimsmglobal'
                    - 'router_multicast6_pimsmglobal_rpaddress'
                    - 'router_multicast_interface'
                    - 'router_multicast_interface_igmp'
                    - 'router_multicast_interface_joingroup'
                    - 'router_multicast_pimsmglobal'
                    - 'router_multicast_pimsmglobal_rpaddress'
                    - 'router_multicast_pimsmglobalvrf'
                    - 'router_multicast_pimsmglobalvrf_rpaddress'
                    - 'router_multicastflow'
                    - 'router_multicastflow_flows'
                    - 'router_ospf'
                    - 'router_ospf6'
                    - 'router_ospf6_area'
                    - 'router_ospf6_area_ipseckeys'
                    - 'router_ospf6_area_range'
                    - 'router_ospf6_area_virtuallink'
                    - 'router_ospf6_area_virtuallink_ipseckeys'
                    - 'router_ospf6_ospf6interface'
                    - 'router_ospf6_ospf6interface_ipseckeys'
                    - 'router_ospf6_ospf6interface_neighbor'
                    - 'router_ospf6_redistribute'
                    - 'router_ospf6_summaryaddress'
                    - 'router_ospf_area'
                    - 'router_ospf_area_filterlist'
                    - 'router_ospf_area_range'
                    - 'router_ospf_area_virtuallink'
                    - 'router_ospf_area_virtuallink_md5keys'
                    - 'router_ospf_distributelist'
                    - 'router_ospf_neighbor'
                    - 'router_ospf_network'
                    - 'router_ospf_ospfinterface'
                    - 'router_ospf_ospfinterface_md5keys'
                    - 'router_ospf_redistribute'
                    - 'router_ospf_summaryaddress'
                    - 'router_policy'
                    - 'router_policy6'
                    - 'router_rip'
                    - 'router_rip_distance'
                    - 'router_rip_distributelist'
                    - 'router_rip_interface'
                    - 'router_rip_neighbor'
                    - 'router_rip_network'
                    - 'router_rip_offsetlist'
                    - 'router_rip_redistribute'
                    - 'router_ripng'
                    - 'router_ripng_aggregateaddress'
                    - 'router_ripng_distance'
                    - 'router_ripng_distributelist'
                    - 'router_ripng_interface'
                    - 'router_ripng_neighbor'
                    - 'router_ripng_network'
                    - 'router_ripng_offsetlist'
                    - 'router_ripng_redistribute'
                    - 'router_routemap'
                    - 'router_setting'
                    - 'router_static'
                    - 'router_static6'
                    - 'rule_fmwp'
                    - 'rule_otdt'
                    - 'rule_otvp'
                    - 'switchcontroller_8021xsettings'
                    - 'switchcontroller_acl_group'
                    - 'switchcontroller_acl_ingress'
                    - 'switchcontroller_acl_ingress_action'
                    - 'switchcontroller_acl_ingress_classifier'
                    - 'switchcontroller_autoconfig_custom'
                    - 'switchcontroller_autoconfig_custom_switchbinding'
                    - 'switchcontroller_autoconfig_default'
                    - 'switchcontroller_autoconfig_policy'
                    - 'switchcontroller_customcommand'
                    - 'switchcontroller_dsl_policy'
                    - 'switchcontroller_dynamicportpolicy'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_flowtracking'
                    - 'switchcontroller_flowtracking_aggregates'
                    - 'switchcontroller_flowtracking_collectors'
                    - 'switchcontroller_fortilinksettings'
                    - 'switchcontroller_fortilinksettings_nacports'
                    - 'switchcontroller_global'
                    - 'switchcontroller_igmpsnooping'
                    - 'switchcontroller_initialconfig_template'
                    - 'switchcontroller_initialconfig_vlans'
                    - 'switchcontroller_lldpprofile'
                    - 'switchcontroller_lldpprofile_customtlvs'
                    - 'switchcontroller_lldpprofile_medlocationservice'
                    - 'switchcontroller_lldpprofile_mednetworkpolicy'
                    - 'switchcontroller_lldpsettings'
                    - 'switchcontroller_location'
                    - 'switchcontroller_location_addresscivic'
                    - 'switchcontroller_location_coordinates'
                    - 'switchcontroller_location_elinnumber'
                    - 'switchcontroller_macpolicy'
                    - 'switchcontroller_managedswitch'
                    - 'switchcontroller_managedswitch_8021xsettings'
                    - 'switchcontroller_managedswitch_customcommand'
                    - 'switchcontroller_managedswitch_dhcpsnoopingstaticclient'
                    - 'switchcontroller_managedswitch_igmpsnooping'
                    - 'switchcontroller_managedswitch_igmpsnooping_vlans'
                    - 'switchcontroller_managedswitch_ipsourceguard'
                    - 'switchcontroller_managedswitch_ipsourceguard_bindingentry'
                    - 'switchcontroller_managedswitch_mirror'
                    - 'switchcontroller_managedswitch_ports'
                    - 'switchcontroller_managedswitch_ports_dhcpsnoopoption82override'
                    - 'switchcontroller_managedswitch_remotelog'
                    - 'switchcontroller_managedswitch_routeoffloadrouter'
                    - 'switchcontroller_managedswitch_snmpcommunity'
                    - 'switchcontroller_managedswitch_snmpcommunity_hosts'
                    - 'switchcontroller_managedswitch_snmpsysinfo'
                    - 'switchcontroller_managedswitch_snmptrapthreshold'
                    - 'switchcontroller_managedswitch_snmpuser'
                    - 'switchcontroller_managedswitch_staticmac'
                    - 'switchcontroller_managedswitch_stormcontrol'
                    - 'switchcontroller_managedswitch_stpinstance'
                    - 'switchcontroller_managedswitch_stpsettings'
                    - 'switchcontroller_managedswitch_switchlog'
                    - 'switchcontroller_managedswitch_vlan'
                    - 'switchcontroller_nacdevice'
                    - 'switchcontroller_nacsettings'
                    - 'switchcontroller_networkmonitorsettings'
                    - 'switchcontroller_portpolicy'
                    - 'switchcontroller_ptp_interfacepolicy'
                    - 'switchcontroller_ptp_policy'
                    - 'switchcontroller_ptp_profile'
                    - 'switchcontroller_ptp_settings'
                    - 'switchcontroller_qos_dot1pmap'
                    - 'switchcontroller_qos_ipdscpmap'
                    - 'switchcontroller_qos_ipdscpmap_map'
                    - 'switchcontroller_qos_qospolicy'
                    - 'switchcontroller_qos_queuepolicy'
                    - 'switchcontroller_qos_queuepolicy_cosqueue'
                    - 'switchcontroller_remotelog'
                    - 'switchcontroller_securitypolicy_8021x'
                    - 'switchcontroller_securitypolicy_localaccess'
                    - 'switchcontroller_sflow'
                    - 'switchcontroller_snmpcommunity'
                    - 'switchcontroller_snmpcommunity_hosts'
                    - 'switchcontroller_snmpsysinfo'
                    - 'switchcontroller_snmptrapthreshold'
                    - 'switchcontroller_snmpuser'
                    - 'switchcontroller_stormcontrol'
                    - 'switchcontroller_stormcontrolpolicy'
                    - 'switchcontroller_stpinstance'
                    - 'switchcontroller_stpsettings'
                    - 'switchcontroller_switchgroup'
                    - 'switchcontroller_switchinterfacetag'
                    - 'switchcontroller_switchlog'
                    - 'switchcontroller_switchprofile'
                    - 'switchcontroller_system'
                    - 'switchcontroller_trafficpolicy'
                    - 'switchcontroller_trafficsniffer'
                    - 'switchcontroller_trafficsniffer_targetip'
                    - 'switchcontroller_trafficsniffer_targetmac'
                    - 'switchcontroller_trafficsniffer_targetport'
                    - 'switchcontroller_virtualportpool'
                    - 'switchcontroller_vlanpolicy'
                    - 'system_3gmodem_custom'
                    - 'system_5gmodem'
                    - 'system_5gmodem_dataplan'
                    - 'system_5gmodem_modem1'
                    - 'system_5gmodem_modem1_simswitch'
                    - 'system_5gmodem_modem2'
                    - 'system_accprofile'
                    - 'system_accprofile_fwgrppermission'
                    - 'system_accprofile_loggrppermission'
                    - 'system_accprofile_netgrppermission'
                    - 'system_accprofile_sysgrppermission'
                    - 'system_accprofile_utmgrppermission'
                    - 'system_acme'
                    - 'system_acme_accounts'
                    - 'system_admin'
                    - 'system_affinityinterrupt'
                    - 'system_affinitypacketredistribution'
                    - 'system_alias'
                    - 'system_apiuser'
                    - 'system_apiuser_trusthost'
                    - 'system_arptable'
                    - 'system_autoinstall'
                    - 'system_automationaction'
                    - 'system_automationaction_httpheaders'
                    - 'system_automationcondition'
                    - 'system_automationdestination'
                    - 'system_automationstitch'
                    - 'system_automationstitch_actions'
                    - 'system_automationtrigger'
                    - 'system_automationtrigger_fields'
                    - 'system_autoscale'
                    - 'system_autoscript'
                    - 'system_autoupdate_pushupdate'
                    - 'system_autoupdate_schedule'
                    - 'system_autoupdate_tunneling'
                    - 'system_bypass'
                    - 'system_centralmanagement'
                    - 'system_centralmanagement_serverlist'
                    - 'system_clustersync'
                    - 'system_clustersync_sessionsyncfilter'
                    - 'system_clustersync_sessionsyncfilter_customservice'
                    - 'system_console'
                    - 'system_consoleserver'
                    - 'system_consoleserver_entries'
                    - 'system_csf'
                    - 'system_csf_fabricconnector'
                    - 'system_csf_fabricdevice'
                    - 'system_csf_trustedlist'
                    - 'system_ddns'
                    - 'system_dedicatedmgmt'
                    - 'system_deviceupgrade'
                    - 'system_deviceupgrade_knownhamembers'
                    - 'system_dhcp6_server'
                    - 'system_dhcp6_server_iprange'
                    - 'system_dhcp6_server_options'
                    - 'system_dhcp6_server_prefixrange'
                    - 'system_digitalio'
                    - 'system_dnp3proxy'
                    - 'system_dns'
                    - 'system_dns64'
                    - 'system_dnsdatabase'
                    - 'system_dnsdatabase_dnsentry'
                    - 'system_dnsserver'
                    - 'system_dscpbasedpriority'
                    - 'system_elbc'
                    - 'system_emailserver'
                    - 'system_evpn'
                    - 'system_fabricvpn'
                    - 'system_fabricvpn_advertisedsubnets'
                    - 'system_fabricvpn_overlays'
                    - 'system_federatedupgrade'
                    - 'system_federatedupgrade_knownhamembers'
                    - 'system_federatedupgrade_nodelist'
                    - 'system_fipscc'
                    - 'system_fortiai'
                    - 'system_fortindr'
                    - 'system_fortisandbox'
                    - 'system_fssopolling'
                    - 'system_ftmpush'
                    - 'system_geneve'
                    - 'system_gigk'
                    - 'system_global'
                    - 'system_gretunnel'
                    - 'system_ha'
                    - 'system_ha_frupsettings'
                    - 'system_ha_hamgmtinterfaces'
                    - 'system_ha_secondaryvcluster'
                    - 'system_ha_unicastpeers'
                    - 'system_ha_vcluster'
                    - 'system_hamonitor'
                    - 'system_healthcheckfortiguard'
                    - 'system_icond'
                    - 'system_ike'
                    - 'system_ike_dhgroup1'
                    - 'system_ike_dhgroup14'
                    - 'system_ike_dhgroup15'
                    - 'system_ike_dhgroup16'
                    - 'system_ike_dhgroup17'
                    - 'system_ike_dhgroup18'
                    - 'system_ike_dhgroup19'
                    - 'system_ike_dhgroup2'
                    - 'system_ike_dhgroup20'
                    - 'system_ike_dhgroup21'
                    - 'system_ike_dhgroup27'
                    - 'system_ike_dhgroup28'
                    - 'system_ike_dhgroup29'
                    - 'system_ike_dhgroup30'
                    - 'system_ike_dhgroup31'
                    - 'system_ike_dhgroup32'
                    - 'system_ike_dhgroup5'
                    - 'system_interface'
                    - 'system_interface_clientoptions'
                    - 'system_interface_dhcpsnoopingserverlist'
                    - 'system_interface_egressqueues'
                    - 'system_interface_ipv6'
                    - 'system_interface_ipv6_clientoptions'
                    - 'system_interface_ipv6_dhcp6iapdlist'
                    - 'system_interface_ipv6_ip6delegatedprefixlist'
                    - 'system_interface_ipv6_ip6dnssllist'
                    - 'system_interface_ipv6_ip6extraaddr'
                    - 'system_interface_ipv6_ip6prefixlist'
                    - 'system_interface_ipv6_ip6rdnsslist'
                    - 'system_interface_ipv6_ip6routelist'
                    - 'system_interface_ipv6_vrrp6'
                    - 'system_interface_l2tpclientsettings'
                    - 'system_interface_mirroringfilter'
                    - 'system_interface_secondaryip'
                    - 'system_interface_tagging'
                    - 'system_interface_vrrp'
                    - 'system_interface_vrrp_proxyarp'
                    - 'system_interface_wifinetworks'
                    - 'system_ipam'
                    - 'system_ipam_pools'
                    - 'system_ipam_pools_exclude'
                    - 'system_ipam_rules'
                    - 'system_ipiptunnel'
                    - 'system_ips'
                    - 'system_ipsecaggregate'
                    - 'system_ipsurlfilterdns'
                    - 'system_ipsurlfilterdns6'
                    - 'system_ipv6neighborcache'
                    - 'system_ipv6tunnel'
                    - 'system_iscsi'
                    - 'system_isfqueueprofile'
                    - 'system_linkmonitor'
                    - 'system_linkmonitor_serverlist'
                    - 'system_lldp_networkpolicy'
                    - 'system_lldp_networkpolicy_guest'
                    - 'system_lldp_networkpolicy_guestvoicesignaling'
                    - 'system_lldp_networkpolicy_softphone'
                    - 'system_lldp_networkpolicy_streamingvideo'
                    - 'system_lldp_networkpolicy_videoconferencing'
                    - 'system_lldp_networkpolicy_videosignaling'
                    - 'system_lldp_networkpolicy_voice'
                    - 'system_lldp_networkpolicy_voicesignaling'
                    - 'system_ltemodem'
                    - 'system_ltemodem_dataplan'
                    - 'system_ltemodem_simswitch'
                    - 'system_macaddresstable'
                    - 'system_memmgr'
                    - 'system_mobiletunnel'
                    - 'system_mobiletunnel_network'
                    - 'system_modem'
                    - 'system_nat64'
                    - 'system_nat64_secondaryprefix'
                    - 'system_ndproxy'
                    - 'system_netflow'
                    - 'system_netflow_collectors'
                    - 'system_netflow_exclusionfilters'
                    - 'system_networkvisibility'
                    - 'system_ngfwsettings'
                    - 'system_np6'
                    - 'system_np6_fpanomaly'
                    - 'system_np6_hpe'
                    - 'system_np6xlite'
                    - 'system_np6xlite_fpanomaly'
                    - 'system_np6xlite_hpe'
                    - 'system_npupost'
                    - 'system_npupost_portnpumap'
                    - 'system_npusetting_prp'
                    - 'system_npuvlink'
                    - 'system_ntp'
                    - 'system_ntp_ntpserver'
                    - 'system_passwordpolicy'
                    - 'system_passwordpolicyguestadmin'
                    - 'system_pcpserver'
                    - 'system_pcpserver_pools'
                    - 'system_physicalswitch'
                    - 'system_pppoeinterface'
                    - 'system_proberesponse'
                    - 'system_proxyarp'
                    - 'system_ptp'
                    - 'system_ptp_serverinterface'
                    - 'system_replacemsg_admin'
                    - 'system_replacemsg_alertmail'
                    - 'system_replacemsg_auth'
                    - 'system_replacemsg_automation'
                    - 'system_replacemsg_custommessage'
                    - 'system_replacemsg_devicedetectionportal'
                    - 'system_replacemsg_fortiguardwf'
                    - 'system_replacemsg_ftp'
                    - 'system_replacemsg_http'
                    - 'system_replacemsg_icap'
                    - 'system_replacemsg_mail'
                    - 'system_replacemsg_mm1'
                    - 'system_replacemsg_mm3'
                    - 'system_replacemsg_mm4'
                    - 'system_replacemsg_mm7'
                    - 'system_replacemsg_mms'
                    - 'system_replacemsg_nacquar'
                    - 'system_replacemsg_nntp'
                    - 'system_replacemsg_spam'
                    - 'system_replacemsg_sslvpn'
                    - 'system_replacemsg_trafficquota'
                    - 'system_replacemsg_utm'
                    - 'system_replacemsg_webproxy'
                    - 'system_saml'
                    - 'system_saml_serviceproviders'
                    - 'system_saml_serviceproviders_assertionattributes'
                    - 'system_sdnvpn'
                    - 'system_sdwan'
                    - 'system_sdwan_duplication'
                    - 'system_sdwan_healthcheck'
                    - 'system_sdwan_healthcheck_sla'
                    - 'system_sdwan_healthcheckfortiguard'
                    - 'system_sdwan_healthcheckfortiguard_sla'
                    - 'system_sdwan_members'
                    - 'system_sdwan_neighbor'
                    - 'system_sdwan_service'
                    - 'system_sdwan_service_sla'
                    - 'system_sdwan_zone'
                    - 'system_securityrating_controls'
                    - 'system_securityrating_settings'
                    - 'system_sessionhelper'
                    - 'system_sessionttl'
                    - 'system_sessionttl_port'
                    - 'system_settings'
                    - 'system_sflow'
                    - 'system_sflow_collectors'
                    - 'system_sittunnel'
                    - 'system_smcntp'
                    - 'system_smcntp_ntpserver'
                    - 'system_snmp_community'
                    - 'system_snmp_community_hosts'
                    - 'system_snmp_community_hosts6'
                    - 'system_snmp_mibview'
                    - 'system_snmp_rmonstat'
                    - 'system_snmp_sysinfo'
                    - 'system_snmp_user'
                    - 'system_speedtestschedule'
                    - 'system_speedtestserver'
                    - 'system_speedtestserver_host'
                    - 'system_speedtestsetting'
                    - 'system_splitportmode'
                    - 'system_sshconfig'
                    - 'system_ssoadmin'
                    - 'system_ssoforticloudadmin'
                    - 'system_ssofortigatecloudadmin'
                    - 'system_standalonecluster'
                    - 'system_standalonecluster_clusterpeer'
                    - 'system_standalonecluster_clusterpeer_sessionsyncfilter'
                    - 'system_standalonecluster_clusterpeer_sessionsyncfilter_customservice'
                    - 'system_standalonecluster_monitorprefix'
                    - 'system_storage'
                    - 'system_stp'
                    - 'system_switchinterface'
                    - 'system_timezone'
                    - 'system_tosbasedpriority'
                    - 'system_vdom'
                    - 'system_vdomdns'
                    - 'system_vdomexception'
                    - 'system_vdomlink'
                    - 'system_vdomnetflow'
                    - 'system_vdomnetflow_collectors'
                    - 'system_vdomproperty'
                    - 'system_vdomradiusserver'
                    - 'system_vdomsflow'
                    - 'system_vdomsflow_collectors'
                    - 'system_vinalarm'
                    - 'system_virtualswitch'
                    - 'system_virtualswitch_port'
                    - 'system_virtualwanlink'
                    - 'system_virtualwanlink_healthcheck'
                    - 'system_virtualwanlink_healthcheck_sla'
                    - 'system_virtualwanlink_members'
                    - 'system_virtualwanlink_neighbor'
                    - 'system_virtualwanlink_service'
                    - 'system_virtualwanlink_service_sla'
                    - 'system_vneinterface'
                    - 'system_vnetunnel'
                    - 'system_vpce'
                    - 'system_vxlan'
                    - 'system_wccp'
                    - 'system_wireless_apstatus'
                    - 'system_wireless_settings'
                    - 'system_zone'
                    - 'system_zone_tagging'
                    - 'user_nacpolicy'
                    - 'user_quarantine'
                    - 'user_quarantine_targets'
                    - 'user_quarantine_targets_macs'
                    - 'user_scim'
                    - 'user_setting'
                    - 'user_setting_authports'
                    - 'videofilter_youtubekey'
                    - 'vpn_certificate_crl'
                    - 'vpn_certificate_local'
                    - 'vpn_certificate_setting'
                    - 'vpn_certificate_setting_crlverification'
                    - 'vpn_ipsec_concentrator'
                    - 'vpn_ipsec_forticlient'
                    - 'vpn_ipsec_manualkey'
                    - 'vpn_ipsec_manualkeyinterface'
                    - 'vpn_ipsec_phase1'
                    - 'vpn_ipsec_phase1_ipv4excluderange'
                    - 'vpn_ipsec_phase1_ipv6excluderange'
                    - 'vpn_ipsec_phase1interface'
                    - 'vpn_ipsec_phase1interface_ipv4excluderange'
                    - 'vpn_ipsec_phase1interface_ipv6excluderange'
                    - 'vpn_ipsec_phase2'
                    - 'vpn_ipsec_phase2interface'
                    - 'vpn_kmipserver'
                    - 'vpn_kmipserver_serverlist'
                    - 'vpn_l2tp'
                    - 'vpn_ocvpn'
                    - 'vpn_ocvpn_forticlientaccess'
                    - 'vpn_ocvpn_forticlientaccess_authgroups'
                    - 'vpn_ocvpn_overlays'
                    - 'vpn_ocvpn_overlays_subnets'
                    - 'vpn_pptp'
                    - 'vpn_qkd'
                    - 'vpn_ssl_client'
                    - 'vpn_ssl_settings'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnsslweb_userbookmark'
                    - 'vpnsslweb_userbookmark_bookmarks'
                    - 'vpnsslweb_userbookmark_bookmarks_formdata'
                    - 'vpnsslweb_usergroupbookmark'
                    - 'vpnsslweb_usergroupbookmark_bookmarks'
                    - 'vpnsslweb_usergroupbookmark_bookmarks_formdata'
                    - 'wanopt_cacheservice'
                    - 'wanopt_cacheservice_dstpeer'
                    - 'wanopt_cacheservice_srcpeer'
                    - 'wanopt_contentdeliverynetworkrule'
                    - 'wanopt_contentdeliverynetworkrule_rules'
                    - 'wanopt_contentdeliverynetworkrule_rules_contentid'
                    - 'wanopt_contentdeliverynetworkrule_rules_matchentries'
                    - 'wanopt_contentdeliverynetworkrule_rules_skipentries'
                    - 'wanopt_remotestorage'
                    - 'wanopt_settings'
                    - 'wanopt_webcache'
                    - 'webfilter_fortiguard'
                    - 'webfilter_ftgdlocalrisk'
                    - 'webfilter_ftgdrisklevel'
                    - 'webfilter_ipsurlfiltercachesetting'
                    - 'webfilter_ipsurlfiltersetting'
                    - 'webfilter_ipsurlfiltersetting6'
                    - 'webfilter_override'
                    - 'webfilter_searchengine'
                    - 'webproxy_debugurl'
                    - 'webproxy_explicit'
                    - 'webproxy_explicit_pacpolicy'
                    - 'webproxy_fastfallback'
                    - 'webproxy_global'
                    - 'webproxy_urlmatch'
                    - 'wireless_accesscontrollist'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_apcfgprofile'
                    - 'wireless_apcfgprofile_commandlist'
                    - 'wireless_apstatus'
                    - 'wireless_arrpprofile'
                    - 'wireless_bleprofile'
                    - 'wireless_bonjourprofile'
                    - 'wireless_bonjourprofile_policylist'
                    - 'wireless_global'
                    - 'wireless_hotspot20_anqp3gppcellular'
                    - 'wireless_hotspot20_anqp3gppcellular_mccmnclist'
                    - 'wireless_hotspot20_anqpipaddresstype'
                    - 'wireless_hotspot20_anqpnairealm'
                    - 'wireless_hotspot20_anqpnairealm_nailist'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam'
                    - 'wireless_hotspot20_anqpnetworkauthtype'
                    - 'wireless_hotspot20_anqproamingconsortium'
                    - 'wireless_hotspot20_anqproamingconsortium_oilist'
                    - 'wireless_hotspot20_anqpvenuename'
                    - 'wireless_hotspot20_anqpvenuename_valuelist'
                    - 'wireless_hotspot20_anqpvenueurl'
                    - 'wireless_hotspot20_anqpvenueurl_valuelist'
                    - 'wireless_hotspot20_h2qpadviceofcharge'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo'
                    - 'wireless_hotspot20_h2qpconncapability'
                    - 'wireless_hotspot20_h2qpoperatorname'
                    - 'wireless_hotspot20_h2qpoperatorname_valuelist'
                    - 'wireless_hotspot20_h2qposuprovider'
                    - 'wireless_hotspot20_h2qposuprovider_friendlyname'
                    - 'wireless_hotspot20_h2qposuprovider_servicedescription'
                    - 'wireless_hotspot20_h2qposuprovidernai'
                    - 'wireless_hotspot20_h2qposuprovidernai_nailist'
                    - 'wireless_hotspot20_h2qptermsandconditions'
                    - 'wireless_hotspot20_h2qpwanmetric'
                    - 'wireless_hotspot20_hsprofile'
                    - 'wireless_hotspot20_icon'
                    - 'wireless_hotspot20_icon_iconlist'
                    - 'wireless_hotspot20_qosmap'
                    - 'wireless_hotspot20_qosmap_dscpexcept'
                    - 'wireless_hotspot20_qosmap_dscprange'
                    - 'wireless_intercontroller'
                    - 'wireless_intercontroller_intercontrollerpeer'
                    - 'wireless_log'
                    - 'wireless_mpskprofile'
                    - 'wireless_mpskprofile_mpskgroup'
                    - 'wireless_mpskprofile_mpskgroup_mpskkey'
                    - 'wireless_nacprofile'
                    - 'wireless_qosprofile'
                    - 'wireless_region'
                    - 'wireless_setting'
                    - 'wireless_setting_offendingssid'
                    - 'wireless_snmp'
                    - 'wireless_snmp_community'
                    - 'wireless_snmp_community_hosts'
                    - 'wireless_snmp_user'
                    - 'wireless_ssidpolicy'
                    - 'wireless_syslogprofile'
                    - 'wireless_timers'
                    - 'wireless_utmprofile'
                    - 'wireless_vap'
                    - 'wireless_vap_dynamicmapping'
                    - 'wireless_vap_macfilterlist'
                    - 'wireless_vap_mpskkey'
                    - 'wireless_vap_portalmessageoverrides'
                    - 'wireless_vap_vlanname'
                    - 'wireless_vap_vlanpool'
                    - 'wireless_vapgroup'
                    - 'wireless_wagprofile'
                    - 'wireless_widsprofile'
                    - 'wireless_wtp'
                    - 'wireless_wtp_lan'
                    - 'wireless_wtp_radio1'
                    - 'wireless_wtp_radio2'
                    - 'wireless_wtp_radio3'
                    - 'wireless_wtp_radio4'
                    - 'wireless_wtp_splittunnelingacl'
                    - 'wireless_wtpgroup'
                    - 'wireless_wtpprofile'
                    - 'wireless_wtpprofile_denymaclist'
                    - 'wireless_wtpprofile_eslsesdongle'
                    - 'wireless_wtpprofile_lan'
                    - 'wireless_wtpprofile_lbs'
                    - 'wireless_wtpprofile_platform'
                    - 'wireless_wtpprofile_radio1'
                    - 'wireless_wtpprofile_radio2'
                    - 'wireless_wtpprofile_radio3'
                    - 'wireless_wtpprofile_radio4'
                    - 'wireless_wtpprofile_splittunnelingacl'
                    - 'ztna_reverseconnector'
                    - 'ztna_trafficforwardproxy'
                    - 'ztna_trafficforwardproxy_quic'
                    - 'ztna_trafficforwardproxy_sslciphersuites'
                    - 'ztna_trafficforwardproxy_sslserverciphersuites'
                    - 'ztna_trafficforwardproxyreverseservice'
                    - 'ztna_trafficforwardproxyreverseservice_remoteservers'
                    - 'ztna_webportal'
                    - 'ztna_webportalbookmark'
                    - 'ztna_webportalbookmark_bookmarks'
                    - 'ztna_webproxy'
                    - 'ztna_webproxy_apigateway'
                    - 'ztna_webproxy_apigateway6'
                    - 'ztna_webproxy_apigateway6_quic'
                    - 'ztna_webproxy_apigateway6_realservers'
                    - 'ztna_webproxy_apigateway6_sslciphersuites'
                    - 'ztna_webproxy_apigateway_quic'
                    - 'ztna_webproxy_apigateway_realservers'
                    - 'ztna_webproxy_apigateway_sslciphersuites'
            fields:
                required: false
                description:
                    - Limit the output by returning only the attributes specified in the string array.
                    - If none specified, all attributes will be returned.
                type: list
                elements: raw
            filter:
                required: false
                description: Filter the result according to a set of criteria.
                type: list
                elements: raw
            option:
                required: false
                description:
                    - Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.
                    - See more details in FNDN API documents.
                type: raw
            sortings:
                required: false
                description: Sorting rules list. Items are returned in ascending(1) or descending(-1) order of fields in the list.
                type: list
                elements: raw
            params:
                required: false
                description: The specific parameters for each different selector.
                type: dict
            extra_params:
                required: false
                description: Extra parameters for each different selector.
                type: dict
'''

EXAMPLES = '''
- name: Gathering fortimanager device facts
  hosts: fortimanagers
  connection: httpapi
  vars:
    device_name: "XXXXXXX"
    vdom_name: "root"
  tasks:
    - name: Gathering fortimanager device fact
      fortinet.fmgdevice.fmgd_fact:
        facts:
          selector: "alertemail_setting"
          params:
            device: "{{ device_name }}"
            vdom: "{{ vdom_name }}"
      register: response
    - name: Display response
      debug:
        var: response
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
    facts_metadata = {
        'alertemail_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/alertemail/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'antivirus_exemptlist': {
            'params': ['device', 'exempt-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/exempt-list',
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/exempt-list/{exempt-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'antivirus_heuristic': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/antivirus/heuristic'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'antivirus_quarantine': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/quarantine'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'antivirus_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'application_name': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/application/name'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'application_rulesettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/rule-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'automation_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/automation/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'aws_vpce': {
            'params': ['device', 'vpce'],
            'urls': [
                '/pm/config/device/{device}/global/aws/vpce',
                '/pm/config/device/{device}/global/aws/vpce/{vpce}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'azure_vwaningresspublicips': {
            'params': ['device', 'vwan-ingress-public-IPs'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-ingress-public-IPs',
                '/pm/config/device/{device}/global/azure/vwan-ingress-public-IPs/{vwan-ingress-public-IPs}'
            ],
            'v_range': [['7.4.4', '']]
        },
        'azure_vwanslb': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb'
            ],
            'v_range': [['7.4.3', '']]
        },
        'azure_vwanslb_permanentsecurityrules': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/permanent-security-rules'
            ],
            'v_range': [['7.4.3', '']]
        },
        'azure_vwanslb_permanentsecurityrules_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/permanent-security-rules/rules',
                '/pm/config/device/{device}/global/azure/vwan-slb/permanent-security-rules/rules/{rules}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'azure_vwanslb_temporarysecurityrules': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/temporary-security-rules'
            ],
            'v_range': [['7.4.3', '']]
        },
        'azure_vwanslb_temporarysecurityrules_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/temporary-security-rules/rules',
                '/pm/config/device/{device}/global/azure/vwan-slb/temporary-security-rules/rules/{rules}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'casb_attributematch': {
            'params': ['attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match',
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_attributematch_attribute': {
            'params': ['attribute', 'attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/attribute',
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/attribute/{attribute}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'certificate_remote': {
            'params': ['device', 'remote'],
            'urls': [
                '/pm/config/device/{device}/global/certificate/remote',
                '/pm/config/device/{device}/global/certificate/remote/{remote}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'dlp_exactdatamatch': {
            'params': ['device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match',
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['columns', 'device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}/columns',
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'dlp_fpdocsource': {
            'params': ['device', 'fp-doc-source', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/fp-doc-source',
                '/pm/config/device/{device}/vdom/{vdom}/dlp/fp-doc-source/{fp-doc-source}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'dlp_settings': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/dlp/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'dpdk_cpus': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/dpdk/cpus'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'dpdk_global': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/dpdk/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'emailfilter_fortiguard': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/emailfilter/fortiguard'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'endpointcontrol_fctemsoverride': {
            'params': ['device', 'fctems-override', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/fctems-override',
                '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/fctems-override/{fctems-override}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'endpointcontrol_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ethernetoam_cfm': {
            'params': ['cfm', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm',
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm/{cfm}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'ethernetoam_cfm_service': {
            'params': ['cfm', 'device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm/{cfm}/service',
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm/{cfm}/service/{service}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'extendercontroller_extender': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender',
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_controllerreport': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/controller-report'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_modem1': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/modem1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_modem1_autoswitch': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/modem1/auto-switch'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_modem2': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/modem2'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_modem2_autoswitch': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/modem2/auto-switch'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extendercontroller_extender_wanextension': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/wan-extension'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_extender': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender',
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender/{extender}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_extender_wanextension': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender/{extender}/wan-extension'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_extendervap': {
            'params': ['device', 'extender-vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-vap',
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-vap/{extender-vap}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'extensioncontroller_fortigate': {
            'params': ['device', 'fortigate', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate',
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate/{fortigate}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_fortigateprofile': {
            'params': ['device', 'fortigate-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate-profile',
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate-profile/{fortigate-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_fortigateprofile_lanextension': {
            'params': ['device', 'fortigate-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate-profile/{fortigate-profile}/lan-extension'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'v_range': [['7.2.6', '7.2.9']]
        },
        'firewall_accessproxysshclientcert_certextension': {
            'params': ['access-proxy-ssh-client-cert', 'cert-extension', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}'
            ],
            'v_range': [['7.2.6', '7.2.9']]
        },
        'firewall_authportal': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/auth-portal'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_dnstranslation': {
            'params': ['device', 'dnstranslation', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/dnstranslation',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/dnstranslation/{dnstranslation}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_global': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceappend': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-append'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition': {
            'params': ['device', 'internet-service-definition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition',
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry': {
            'params': ['device', 'entry', 'internet-service-definition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry',
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry_portrange': {
            'params': ['device', 'entry', 'internet-service-definition', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}/port-range',
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}/port-range/{port-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension': {
            'params': ['device', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_ip6range': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'ip6-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-ra'
                'nge',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-ra'
                'nge/{ip6-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_iprange': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'ip-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-ran'
                'ge',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-ran'
                'ge/{ip-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_portrange': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'port-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-r'
                'ange',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-r'
                'ange/{port-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_entry': {
            'params': ['device', 'entry', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_entry_portrange': {
            'params': ['device', 'entry', 'internet-service-extension', 'port-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range'
                '}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ipmacbinding_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ipmacbinding/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ipmacbinding_table': {
            'params': ['device', 'table', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ipmacbinding/table',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ipmacbinding/table/{table}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_iptranslation': {
            'params': ['device', 'ip-translation', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ip-translation',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ip-translation/{ip-translation}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ipv6ehfilter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/ipv6-eh-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ondemandsniffer': {
            'params': ['device', 'on-demand-sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/on-demand-sniffer',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/on-demand-sniffer/{on-demand-sniffer}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'firewall_pfcp': {
            'params': ['device', 'pfcp', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/pfcp',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/pfcp/{pfcp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy/{policy}'
            ]
        },
        'firewall_sniffer': {
            'params': ['device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_sniffer_anomaly': {
            'params': ['anomaly', 'device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}/anomaly',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}/anomaly/{anomaly}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssh_hostkey': {
            'params': ['device', 'host-key', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/host-key',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/host-key/{host-key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssh_localkey': {
            'params': ['device', 'local-key', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/local-key',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/local-key/{local-key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssh_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssl_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/ssl/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_sslserver': {
            'params': ['device', 'ssl-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-server',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-server/{ssl-server}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ttlpolicy': {
            'params': ['device', 'ttl-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy/{ttl-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ftpproxy_explicit': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ftp-proxy/explicit'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'gtp_apnshaper': {
            'params': ['apn-shaper', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper',
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper/{apn-shaper}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'gtp_ieallowlist': {
            'params': ['device', 'ie-allow-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list',
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}'
            ],
            'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.6.1']]
        },
        'gtp_ieallowlist_entries': {
            'params': ['device', 'entries', 'ie-allow-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}/entries',
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}'
            ],
            'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.6.1']]
        },
        'gtp_rattimeoutprofile': {
            'params': ['device', 'rat-timeout-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/rat-timeout-profile',
                '/pm/config/device/{device}/vdom/{vdom}/gtp/rat-timeout-profile/{rat-timeout-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'icap_profile': {
            'params': ['device', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/profile',
                '/pm/config/device/{device}/vdom/{vdom}/icap/profile/{profile}'
            ]
        },
        'icap_server': {
            'params': ['device', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server',
                '/pm/config/device/{device}/vdom/{vdom}/icap/server/{server}'
            ]
        },
        'icap_servergroup': {
            'params': ['device', 'server-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group',
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'icap_servergroup_serverlist': {
            'params': ['device', 'server-group', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}/server-list',
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}/server-list/{server-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_decoder': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/ips/decoder'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_decoder_parameter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/ips/decoder/parameter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_global': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/ips/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_rule': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/ips/rule'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_rulesettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/rule-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ips_tlsactiveprobe': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/ips/global/tls-active-probe'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_flowrule': {
            'params': ['device', 'flow-rule'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/flow-rule',
                '/pm/config/device/{device}/global/load-balance/flow-rule/{flow-rule}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_setting_workers': {
            'params': ['device', 'workers'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/setting/workers',
                '/pm/config/device/{device}/global/load-balance/setting/workers/{workers}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_workergroup': {
            'params': ['device', 'worker-group'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/worker-group',
                '/pm/config/device/{device}/global/load-balance/worker-group/{worker-group}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'log_azuresecuritycenter2_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/filter/free-style',
                '/pm/config/device/{device}/global/log/azure-security-center2/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/azure-security-center2/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/filter/free-style',
                '/pm/config/device/{device}/global/log/azure-security-center/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/azure-security-center/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_disk_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_disk_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_disk_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_eventfilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/eventfilter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer2/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer2/filter/free-style',
                '/pm/config/device/{device}/global/log/fortianalyzer2/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer2/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer3/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer3/filter/free-style',
                '/pm/config/device/{device}/global/log/fortianalyzer3/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer3/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer/filter/free-style',
                '/pm/config/device/{device}/global/log/fortianalyzer/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/filter/free-style',
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortiguard/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortiguard/filter/free-style',
                '/pm/config/device/{device}/global/log/fortiguard/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortiguard/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_guidisplay': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/gui-display'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_memory_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_memory_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_memory_globalsetting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/memory/global-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_memory_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_nulldevice_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_nulldevice_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_nulldevice_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_slbc_globalsetting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/slbc/global-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/filter/free-style',
                '/pm/config/device/{device}/global/log/syslogd2/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting/custom-field-name',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/syslogd2/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/filter/free-style',
                '/pm/config/device/{device}/global/log/syslogd3/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting/custom-field-name',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/syslogd3/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/filter/free-style',
                '/pm/config/device/{device}/global/log/syslogd4/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting/custom-field-name',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/syslogd4/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/filter/free-style',
                '/pm/config/device/{device}/global/log/syslogd/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridefilter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter/free-style',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridesetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting/custom-field-name',
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/setting/custom-field-name',
                '/pm/config/device/{device}/global/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting2_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting2/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting2_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting2/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting3_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting3/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting3_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting3/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting_filter': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_tacacsaccounting_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/tacacs+accounting/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_webtrends_filter': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/webtrends/filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_webtrends_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/webtrends/filter/free-style',
                '/pm/config/device/{device}/global/log/webtrends/filter/free-style/{free-style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_webtrends_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/log/webtrends/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'monitoring_np6ipsecengine': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/monitoring/np6-ipsec-engine'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'monitoring_npuhpe': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/monitoring/npu-hpe'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'notification': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/notification'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsx_profile': {
            'params': ['device', 'profile'],
            'urls': [
                '/pm/config/device/{device}/global/nsx/profile',
                '/pm/config/device/{device}/global/nsx/profile/{profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_servicechain': {
            'params': ['device', 'service-chain'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain',
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_servicechain_serviceindex': {
            'params': ['device', 'service-chain', 'service-index'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index',
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index/{service-index}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_setting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'pfcp_messagefilter': {
            'params': ['device', 'message-filter', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/pfcp/message-filter',
                '/pm/config/device/{device}/vdom/{vdom}/pfcp/message-filter/{message-filter}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart',
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_categoryseries': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/category-series'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_column': {
            'params': ['chart', 'column', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column',
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_column_mapping': {
            'params': ['chart', 'column', 'device', 'mapping', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}/mapping',
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}/mapping/{mapping}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_drilldowncharts': {
            'params': ['chart', 'device', 'drill-down-charts', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/drill-down-charts',
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/drill-down-charts/{drill-down-charts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_valueseries': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/value-series'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_xseries': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/x-series'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_yseries': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/y-series'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset': {
            'params': ['dataset', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset',
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset_field': {
            'params': ['dataset', 'device', 'field', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/field',
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/field/{field}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset_parameters': {
            'params': ['dataset', 'device', 'parameters', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/parameters',
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/parameters/{parameters}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout': {
            'params': ['device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem': {
            'params': ['body-item', 'device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_list': {
            'params': ['body-item', 'device', 'layout', 'list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/list',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/list/{list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_parameters': {
            'params': ['body-item', 'device', 'layout', 'parameters', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/parameters',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/parameters/{parameters}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page': {
            'params': ['device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_footer': {
            'params': ['device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_footer_footeritem': {
            'params': ['device', 'footer-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item/{footer-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_header': {
            'params': ['device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_header_headeritem': {
            'params': ['device', 'header-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item',
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item/{header-item}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_style': {
            'params': ['device', 'style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/style',
                '/pm/config/device/{device}/vdom/{vdom}/report/style/{style}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_theme': {
            'params': ['device', 'theme', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/theme',
                '/pm/config/device/{device}/vdom/{vdom}/report/theme/{theme}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_authpath': {
            'params': ['auth-path', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/auth-path',
                '/pm/config/device/{device}/vdom/{vdom}/router/auth-path/{auth-path}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd6_multihoptemplate': {
            'params': ['device', 'multihop-template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/multihop-template',
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/multihop-template/{multihop-template}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd6_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd_multihoptemplate': {
            'params': ['device', 'multihop-template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/multihop-template',
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/multihop-template/{multihop-template}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_admindistance': {
            'params': ['admin-distance', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/admin-distance',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/admin-distance/{admin-distance}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress': {
            'params': ['aggregate-address', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address/{aggregate-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress6': {
            'params': ['aggregate-address6', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address6/{aggregate-address6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor_conditionaladvertise': {
            'params': ['conditional-advertise', 'device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise/{conditional-advertise}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor_conditionaladvertise6': {
            'params': ['conditional-advertise6', 'device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise6/{conditional-advertise6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborgroup': {
            'params': ['device', 'neighbor-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-group',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-group/{neighbor-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange': {
            'params': ['device', 'neighbor-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range/{neighbor-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange6': {
            'params': ['device', 'neighbor-range6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range6/{neighbor-range6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network/{network}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_network6': {
            'params': ['device', 'network6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network6/{network6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_redistribute6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/redistribute6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf': {
            'params': ['device', 'vdom', 'vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf/{vrf}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf6': {
            'params': ['device', 'vdom', 'vrf6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6/{vrf6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf6_leaktarget': {
            'params': ['device', 'leak-target', 'vdom', 'vrf6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6/{vrf6}/leak-target',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6/{vrf6}/leak-target/{leak-target}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf_leaktarget': {
            'params': ['device', 'leak-target', 'vdom', 'vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf/{vrf}/leak-target',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf/{vrf}/leak-target/{leak-target}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak': {
            'params': ['device', 'vdom', 'vrf-leak'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak/{vrf-leak}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak6': {
            'params': ['device', 'vdom', 'vrf-leak6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6/{vrf-leak6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak6_target': {
            'params': ['device', 'target', 'vdom', 'vrf-leak6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6/{vrf-leak6}/target',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6/{vrf-leak6}/target/{target}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak_target': {
            'params': ['device', 'target', 'vdom', 'vrf-leak'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak/{vrf-leak}/target',
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak/{vrf-leak}/target/{target}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_extcommunitylist': {
            'params': ['device', 'extcommunity-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_extcommunitylist_rule': {
            'params': ['device', 'extcommunity-list', 'rule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}/rule',
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}/rule/{rule}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_isisinterface': {
            'params': ['device', 'isis-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-interface/{isis-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_isisnet': {
            'params': ['device', 'isis-net', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-net',
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-net/{isis-net}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_redistribute6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/redistribute6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address/{summary-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress6': {
            'params': ['device', 'summary-address6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address6',
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address6/{summary-address6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_keychain': {
            'params': ['device', 'key-chain', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain',
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_keychain_key': {
            'params': ['device', 'key', 'key-chain', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}/key',
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}/key/{key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/interface/{interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6_pimsmglobal': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6_pimsmglobal_rpaddress': {
            'params': ['device', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global/rp-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global/rp-address/{rp-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_interface_igmp': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}/igmp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_interface_joingroup': {
            'params': ['device', 'interface', 'join-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}/join-group',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}/join-group/{join-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobal': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobal_rpaddress': {
            'params': ['device', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global/rp-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global/rp-address/{rp-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobalvrf': {
            'params': ['device', 'pim-sm-global-vrf', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'router_multicast_pimsmglobalvrf_rpaddress': {
            'params': ['device', 'pim-sm-global-vrf', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}/rp-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}/rp-address/{rp-address}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'router_multicastflow': {
            'params': ['device', 'multicast-flow', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicastflow_flows': {
            'params': ['device', 'flows', 'multicast-flow', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}/flows',
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}/flows/{flows}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area': {
            'params': ['area', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_ipseckeys': {
            'params': ['area', 'device', 'ipsec-keys', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/ipsec-keys',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/ipsec-keys/{ipsec-keys}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_range': {
            'params': ['area', 'device', 'range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/range',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/range/{range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink': {
            'params': ['area', 'device', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink_ipseckeys': {
            'params': ['area', 'device', 'ipsec-keys', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}/ipsec-keys',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}/ipsec-keys/{ipsec-keys}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface': {
            'params': ['device', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_ipseckeys': {
            'params': ['device', 'ipsec-keys', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/ipsec-keys',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/ipsec-keys/{ipsec-keys}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_neighbor': {
            'params': ['device', 'neighbor', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/summary-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/summary-address/{summary-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area': {
            'params': ['area', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_filterlist': {
            'params': ['area', 'device', 'filter-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/filter-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/filter-list/{filter-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_range': {
            'params': ['area', 'device', 'range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/range',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/range/{range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink': {
            'params': ['area', 'device', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink_md5keys': {
            'params': ['area', 'device', 'md5-keys', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}/md5-keys',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}/md5-keys/{md5-keys}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/distribute-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/distribute-list/{distribute-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/network',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/network/{network}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface': {
            'params': ['device', 'ospf-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface_md5keys': {
            'params': ['device', 'md5-keys', 'ospf-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}/md5-keys',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}/md5-keys/{md5-keys}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/summary-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/summary-address/{summary-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy',
                '/pm/config/device/{device}/vdom/{vdom}/router/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy6': {
            'params': ['device', 'policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6',
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6/{policy6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_distance': {
            'params': ['device', 'distance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distance',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distance/{distance}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distribute-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distribute-list/{distribute-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/interface/{interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/network',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/network/{network}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_offsetlist': {
            'params': ['device', 'offset-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/offset-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/offset-list/{offset-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_aggregateaddress': {
            'params': ['aggregate-address', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/aggregate-address',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/aggregate-address/{aggregate-address}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_distance': {
            'params': ['device', 'distance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distance',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distance/{distance}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distribute-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distribute-list/{distribute-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/interface',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/interface/{interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/network',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/network/{network}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_offsetlist': {
            'params': ['device', 'offset-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/offset-list',
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/offset-list/{offset-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_redistribute': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/redistribute'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_routemap': {
            'params': ['device', 'route-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/route-map',
                '/pm/config/device/{device}/vdom/{vdom}/router/route-map/{route-map}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_static': {
            'params': ['device', 'static', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static',
                '/pm/config/device/{device}/vdom/{vdom}/router/static/{static}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_static6': {
            'params': ['device', 'static6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static6',
                '/pm/config/device/{device}/vdom/{vdom}/router/static6/{static6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'rule_fmwp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/rule/fmwp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'rule_otdt': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/rule/otdt'
            ],
            'v_range': [['7.4.3', '']]
        },
        'rule_otvp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/rule/otvp'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_8021xsettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/802-1X-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_acl_group': {
            'params': ['device', 'group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/group',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/group/{group}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_acl_ingress': {
            'params': ['device', 'ingress', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress/{ingress}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_acl_ingress_action': {
            'params': ['device', 'ingress', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress/{ingress}/action'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_acl_ingress_classifier': {
            'params': ['device', 'ingress', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress/{ingress}/classifier'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom': {
            'params': ['custom', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom_switchbinding': {
            'params': ['custom', 'device', 'switch-binding', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}/switch-binding',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}/switch-binding/{switch-binding}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_default': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/default'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_customcommand': {
            'params': ['custom-command', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/custom-command',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/custom-command/{custom-command}',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global/custom-command',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global/custom-command/{custom-command}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dsl_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dsl/policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dsl/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy': {
            'params': ['device', 'dynamic-port-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['device', 'dynamic-port-policy', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_aggregates': {
            'params': ['aggregates', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/aggregates',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/aggregates/{aggregates}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_collectors': {
            'params': ['collectors', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/collectors',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/collectors/{collectors}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_fortilinksettings': {
            'params': ['device', 'fortilink-settings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_fortilinksettings_nacports': {
            'params': ['device', 'fortilink-settings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings/{fortilink-settings}/nac-ports'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_global': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_igmpsnooping': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/igmp-snooping'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_initialconfig_template': {
            'params': ['device', 'template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/initial-config/template',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/initial-config/template/{template}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_initialconfig_vlans': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/initial-config/vlans'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile': {
            'params': ['device', 'lldp-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': ['custom-tlvs', 'device', 'lldp-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': ['device', 'lldp-profile', 'med-location-service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-location-service',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': ['device', 'lldp-profile', 'med-network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-network-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpsettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_location': {
            'params': ['device', 'location', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_location_addresscivic': {
            'params': ['device', 'location', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}/address-civic'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_location_coordinates': {
            'params': ['device', 'location', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}/coordinates'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_location_elinnumber': {
            'params': ['device', 'location', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}/elin-number'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_macpolicy': {
            'params': ['device', 'mac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/mac-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/mac-policy/{mac-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_8021xsettings': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/802-1X-settings'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': ['custom-command', 'device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/custom-command',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': ['device', 'dhcp-snooping-static-client', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-c'
                'lient}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_igmpsnooping': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_igmpsnooping_vlans': {
            'params': ['device', 'managed-switch', 'vdom', 'vlans'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping/vlans',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping/vlans/{vlans}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': ['device', 'ip-source-guard', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': ['binding-entry', 'device', 'ip-source-guard', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{bi'
                'nding-entry}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_mirror': {
            'params': ['device', 'managed-switch', 'mirror', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror/{mirror}'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ports': {
            'params': ['device', 'managed-switch', 'ports', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': ['device', 'dhcp-snoop-option82-override', 'managed-switch', 'ports', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-sn'
                'oop-option82-override}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': ['device', 'managed-switch', 'remote-log', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/remote-log',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_routeoffloadrouter': {
            'params': ['device', 'managed-switch', 'route-offload-router', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/route-offload-router',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': ['device', 'managed-switch', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': ['device', 'hosts', 'managed-switch', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpsysinfo': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-sysinfo'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmptrapthreshold': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-trap-threshold'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': ['device', 'managed-switch', 'snmp-user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-user',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_staticmac': {
            'params': ['device', 'managed-switch', 'static-mac', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/static-mac',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/static-mac/{static-mac}'
            ],
            'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_stormcontrol': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/storm-control'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_stpinstance': {
            'params': ['device', 'managed-switch', 'stp-instance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-instance',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-instance/{stp-instance}'
            ],
            'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_stpsettings': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-settings'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_switchlog': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/switch-log'
            ],
            'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_vlan': {
            'params': ['device', 'managed-switch', 'vdom', 'vlan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/vlan',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_nacdevice': {
            'params': ['device', 'nac-device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-device',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-device/{nac-device}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_nacsettings': {
            'params': ['device', 'nac-settings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-settings',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-settings/{nac-settings}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_networkmonitorsettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/network-monitor-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_portpolicy': {
            'params': ['device', 'port-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/port-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/port-policy/{port-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_interfacepolicy': {
            'params': ['device', 'interface-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/interface-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/interface-policy/{interface-policy}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_ptp_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/policy/{policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_profile': {
            'params': ['device', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/profile',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/profile/{profile}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'switchcontroller_ptp_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_dot1pmap': {
            'params': ['device', 'dot1p-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/dot1p-map',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': ['device', 'ip-dscp-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': ['device', 'ip-dscp-map', 'map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_qospolicy': {
            'params': ['device', 'qos-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/qos-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/qos-policy/{qos-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy': {
            'params': ['device', 'queue-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': ['cos-queue', 'device', 'queue-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}/cos-queue',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_remotelog': {
            'params': ['device', 'remote-log', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/remote-log',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/remote-log/{remote-log}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': ['802-1X', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/802-1X',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/802-1X/{802-1X}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_localaccess': {
            'params': ['device', 'local-access', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/local-access',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/local-access/{local-access}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_sflow': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/sflow'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity': {
            'params': ['device', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity_hosts': {
            'params': ['device', 'hosts', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}/hosts',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpsysinfo': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-sysinfo'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmptrapthreshold': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-trap-threshold'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpuser': {
            'params': ['device', 'snmp-user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-user',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-user/{snmp-user}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stormcontrol': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stormcontrolpolicy': {
            'params': ['device', 'storm-control-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control-policy/{storm-control-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stpinstance': {
            'params': ['device', 'stp-instance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/stp-instance',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/stp-instance/{stp-instance}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stpsettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/stp-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchgroup': {
            'params': ['device', 'switch-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-group',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-group/{switch-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchinterfacetag': {
            'params': ['device', 'switch-interface-tag', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-interface-tag',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchlog': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-log'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchprofile': {
            'params': ['device', 'switch-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-profile',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-profile/{switch-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_system': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/switch-controller/system'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficpolicy': {
            'params': ['device', 'traffic-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetip': {
            'params': ['device', 'target-ip', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-ip',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-ip/{target-ip}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetmac': {
            'params': ['device', 'target-mac', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-mac',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-mac/{target-mac}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetport': {
            'params': ['device', 'target-port', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-port',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-port/{target-port}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_virtualportpool': {
            'params': ['device', 'vdom', 'virtual-port-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/virtual-port-pool',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/virtual-port-pool/{virtual-port-pool}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_vlanpolicy': {
            'params': ['device', 'vdom', 'vlan-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/vlan-policy',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_3gmodem_custom': {
            'params': ['custom', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/3g-modem/custom',
                '/pm/config/device/{device}/vdom/{vdom}/system/3g-modem/custom/{custom}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem_dataplan': {
            'params': ['data-plan', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/data-plan',
                '/pm/config/device/{device}/global/system/5g-modem/data-plan/{data-plan}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem_modem1': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/modem1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem_modem1_simswitch': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/modem1/sim-switch'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem_modem2': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/modem2'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile',
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile_fwgrppermission': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}/fwgrp-permission'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile_loggrppermission': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}/loggrp-permission'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile_netgrppermission': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}/netgrp-permission'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile_sysgrppermission': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}/sysgrp-permission'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile_utmgrppermission': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}/utmgrp-permission'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_acme': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/acme'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_acme_accounts': {
            'params': ['accounts', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/acme/accounts',
                '/pm/config/device/{device}/global/system/acme/accounts/{accounts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_admin': {
            'params': ['admin', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/admin',
                '/pm/config/device/{device}/global/system/admin/{admin}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_affinityinterrupt': {
            'params': ['affinity-interrupt', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-interrupt',
                '/pm/config/device/{device}/global/system/affinity-interrupt/{affinity-interrupt}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_affinitypacketredistribution': {
            'params': ['affinity-packet-redistribution', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-packet-redistribution',
                '/pm/config/device/{device}/global/system/affinity-packet-redistribution/{affinity-packet-redistribution}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_alias': {
            'params': ['alias', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/alias',
                '/pm/config/device/{device}/global/system/alias/{alias}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_apiuser': {
            'params': ['api-user', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user',
                '/pm/config/device/{device}/global/system/api-user/{api-user}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_apiuser_trusthost': {
            'params': ['api-user', 'device', 'trusthost'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user/{api-user}/trusthost',
                '/pm/config/device/{device}/global/system/api-user/{api-user}/trusthost/{trusthost}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_arptable': {
            'params': ['arp-table', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/arp-table',
                '/pm/config/device/{device}/vdom/{vdom}/system/arp-table/{arp-table}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoinstall': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/auto-install'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationaction': {
            'params': ['automation-action', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action',
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationaction_httpheaders': {
            'params': ['automation-action', 'device', 'http-headers'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}/http-headers',
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}/http-headers/{http-headers}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationcondition': {
            'params': ['automation-condition', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-condition',
                '/pm/config/device/{device}/global/system/automation-condition/{automation-condition}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_automationdestination': {
            'params': ['automation-destination', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-destination',
                '/pm/config/device/{device}/global/system/automation-destination/{automation-destination}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationstitch': {
            'params': ['automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch',
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationstitch_actions': {
            'params': ['actions', 'automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions',
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions/{actions}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationtrigger': {
            'params': ['automation-trigger', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger',
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationtrigger_fields': {
            'params': ['automation-trigger', 'device', 'fields'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}/fields',
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}/fields/{fields}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoscale': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/auto-scale'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoscript': {
            'params': ['auto-script', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/auto-script',
                '/pm/config/device/{device}/global/system/auto-script/{auto-script}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoupdate_pushupdate': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/autoupdate/push-update'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoupdate_schedule': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/autoupdate/schedule'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoupdate_tunneling': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/autoupdate/tunneling'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_bypass': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/bypass'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_centralmanagement': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/central-management'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_centralmanagement_serverlist': {
            'params': ['device', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/central-management/server-list',
                '/pm/config/device/{device}/global/system/central-management/server-list/{server-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_clustersync': {
            'params': ['cluster-sync', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync',
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_clustersync_sessionsyncfilter': {
            'params': ['cluster-sync', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}/session-sync-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_clustersync_sessionsyncfilter_customservice': {
            'params': ['cluster-sync', 'custom-service', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}/session-sync-filter/custom-service',
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}/session-sync-filter/custom-service/{custom-service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_console': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/console'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_consoleserver': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/console-server'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_consoleserver_entries': {
            'params': ['device', 'entries'],
            'urls': [
                '/pm/config/device/{device}/global/system/console-server/entries',
                '/pm/config/device/{device}/global/system/console-server/entries/{entries}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_fabricconnector': {
            'params': ['device', 'fabric-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-connector',
                '/pm/config/device/{device}/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_fabricdevice': {
            'params': ['device', 'fabric-device'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-device',
                '/pm/config/device/{device}/global/system/csf/fabric-device/{fabric-device}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_trustedlist': {
            'params': ['device', 'trusted-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/trusted-list',
                '/pm/config/device/{device}/global/system/csf/trusted-list/{trusted-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ddns': {
            'params': ['ddns', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ddns',
                '/pm/config/device/{device}/global/system/ddns/{ddns}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dedicatedmgmt': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/dedicated-mgmt'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_deviceupgrade': {
            'params': ['device', 'device-upgrade'],
            'urls': [
                '/pm/config/device/{device}/global/system/device-upgrade',
                '/pm/config/device/{device}/global/system/device-upgrade/{device-upgrade}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_deviceupgrade_knownhamembers': {
            'params': ['device', 'device-upgrade', 'known-ha-members'],
            'urls': [
                '/pm/config/device/{device}/global/system/device-upgrade/{device-upgrade}/known-ha-members',
                '/pm/config/device/{device}/global/system/device-upgrade/{device-upgrade}/known-ha-members/{known-ha-members}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_dhcp6_server': {
            'params': ['device', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server',
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dhcp6_server_iprange': {
            'params': ['device', 'ip-range', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/ip-range',
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/ip-range/{ip-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dhcp6_server_options': {
            'params': ['device', 'options', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/options',
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/options/{options}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_dhcp6_server_prefixrange': {
            'params': ['device', 'prefix-range', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/prefix-range',
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/prefix-range/{prefix-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_digitalio': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/digital-io'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnp3proxy': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/dnp3-proxy'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dns': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/dns'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dns64': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns64'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsdatabase': {
            'params': ['device', 'dns-database', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database',
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsdatabase_dnsentry': {
            'params': ['device', 'dns-database', 'dns-entry', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}/dns-entry',
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}/dns-entry/{dns-entry}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsserver': {
            'params': ['device', 'dns-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-server',
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-server/{dns-server}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dscpbasedpriority': {
            'params': ['device', 'dscp-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/dscp-based-priority',
                '/pm/config/device/{device}/global/system/dscp-based-priority/{dscp-based-priority}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_elbc': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/elbc'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_emailserver': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/email-server'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_evpn': {
            'params': ['device', 'evpn', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/evpn',
                '/pm/config/device/{device}/vdom/{vdom}/system/evpn/{evpn}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_fabricvpn': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fabricvpn_advertisedsubnets': {
            'params': ['advertised-subnets', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/advertised-subnets',
                '/pm/config/device/{device}/global/system/fabric-vpn/advertised-subnets/{advertised-subnets}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fabricvpn_overlays': {
            'params': ['device', 'overlays'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/overlays',
                '/pm/config/device/{device}/global/system/fabric-vpn/overlays/{overlays}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_federatedupgrade': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/federated-upgrade'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_federatedupgrade_knownhamembers': {
            'params': ['device', 'known-ha-members'],
            'urls': [
                '/pm/config/device/{device}/global/system/federated-upgrade/known-ha-members',
                '/pm/config/device/{device}/global/system/federated-upgrade/known-ha-members/{known-ha-members}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_federatedupgrade_nodelist': {
            'params': ['device', 'node-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/federated-upgrade/node-list',
                '/pm/config/device/{device}/global/system/federated-upgrade/node-list/{node-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fipscc': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fips-cc'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fortiai': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fortiai'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fortindr': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fortindr'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fortisandbox': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fortisandbox'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fssopolling': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fsso-polling'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ftmpush': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ftm-push'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_geneve': {
            'params': ['device', 'geneve', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/geneve',
                '/pm/config/device/{device}/vdom/{vdom}/system/geneve/{geneve}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_gigk': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/gi-gk'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_global': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_gretunnel': {
            'params': ['device', 'gre-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/gre-tunnel',
                '/pm/config/device/{device}/vdom/{vdom}/system/gre-tunnel/{gre-tunnel}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_frupsettings': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/frup-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_hamgmtinterfaces': {
            'params': ['device', 'ha-mgmt-interfaces'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/ha-mgmt-interfaces',
                '/pm/config/device/{device}/global/system/ha/ha-mgmt-interfaces/{ha-mgmt-interfaces}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_secondaryvcluster': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/secondary-vcluster'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_unicastpeers': {
            'params': ['device', 'unicast-peers'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/unicast-peers',
                '/pm/config/device/{device}/global/system/ha/unicast-peers/{unicast-peers}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_vcluster': {
            'params': ['device', 'vcluster'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/vcluster',
                '/pm/config/device/{device}/global/system/ha/vcluster/{vcluster}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_hamonitor': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha-monitor'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_healthcheckfortiguard': {
            'params': ['device', 'health-check-fortiguard'],
            'urls': [
                '/pm/config/device/{device}/global/system/health-check-fortiguard',
                '/pm/config/device/{device}/global/system/health-check-fortiguard/{health-check-fortiguard}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_icond': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/icond'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_ike': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup1': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup14': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-14'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup15': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-15'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup16': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-16'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup17': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-17'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup18': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-18'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup19': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-19'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup2': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-2'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup20': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-20'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup21': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-21'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup27': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-27'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup28': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-28'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup29': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-29'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup30': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-30'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup31': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-31'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup32': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-32'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ike_dhgroup5': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ike/dh-group-5'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface',
                '/pm/config/device/{device}/global/system/interface/{interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_clientoptions': {
            'params': ['client-options', 'device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/client-options',
                '/pm/config/device/{device}/global/system/interface/{interface}/client-options/{client-options}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_dhcpsnoopingserverlist': {
            'params': ['device', 'dhcp-snooping-server-list', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/dhcp-snooping-server-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/dhcp-snooping-server-list/{dhcp-snooping-server-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_egressqueues': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/egress-queues'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_clientoptions': {
            'params': ['client-options', 'device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/client-options',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/client-options/{client-options}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_interface_ipv6_dhcp6iapdlist': {
            'params': ['device', 'dhcp6-iapd-list', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/dhcp6-iapd-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/dhcp6-iapd-list/{dhcp6-iapd-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['device', 'interface', 'ip6-delegated-prefix-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-delegated-prefix-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6dnssllist': {
            'params': ['device', 'interface', 'ip6-dnssl-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-dnssl-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-dnssl-list/{ip6-dnssl-list}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_ip6extraaddr': {
            'params': ['device', 'interface', 'ip6-extra-addr'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-extra-addr',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6prefixlist': {
            'params': ['device', 'interface', 'ip6-prefix-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-prefix-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6rdnsslist': {
            'params': ['device', 'interface', 'ip6-rdnss-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-rdnss-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-rdnss-list/{ip6-rdnss-list}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_ip6routelist': {
            'params': ['device', 'interface', 'ip6-route-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-route-list',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-route-list/{ip6-route-list}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_vrrp6': {
            'params': ['device', 'interface', 'vrrp6'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/vrrp6',
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/vrrp6/{vrrp6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_l2tpclientsettings': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/l2tp-client-settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_mirroringfilter': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/mirroring-filter'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_interface_secondaryip': {
            'params': ['device', 'interface', 'secondaryip'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/secondaryip',
                '/pm/config/device/{device}/global/system/interface/{interface}/secondaryip/{secondaryip}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_tagging': {
            'params': ['device', 'interface', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/tagging',
                '/pm/config/device/{device}/global/system/interface/{interface}/tagging/{tagging}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_vrrp': {
            'params': ['device', 'interface', 'vrrp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp',
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_vrrp_proxyarp': {
            'params': ['device', 'interface', 'proxy-arp', 'vrrp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}/proxy-arp',
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_wifinetworks': {
            'params': ['device', 'interface', 'wifi-networks'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/wifi-networks',
                '/pm/config/device/{device}/global/system/interface/{interface}/wifi-networks/{wifi-networks}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipam': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipam_pools': {
            'params': ['device', 'pools'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/pools',
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipam_pools_exclude': {
            'params': ['device', 'exclude', 'pools'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}/exclude',
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}/exclude/{exclude}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_ipam_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/rules',
                '/pm/config/device/{device}/global/system/ipam/rules/{rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipiptunnel': {
            'params': ['device', 'ipip-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipip-tunnel',
                '/pm/config/device/{device}/vdom/{vdom}/system/ipip-tunnel/{ipip-tunnel}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ips': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ips'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsecaggregate': {
            'params': ['device', 'ipsec-aggregate', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipsec-aggregate',
                '/pm/config/device/{device}/vdom/{vdom}/system/ipsec-aggregate/{ipsec-aggregate}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsurlfilterdns': {
            'params': ['device', 'ips-urlfilter-dns'],
            'urls': [
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns',
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns/{ips-urlfilter-dns}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsurlfilterdns6': {
            'params': ['device', 'ips-urlfilter-dns6'],
            'urls': [
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns6',
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns6/{ips-urlfilter-dns6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipv6neighborcache': {
            'params': ['device', 'ipv6-neighbor-cache', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-neighbor-cache',
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-neighbor-cache/{ipv6-neighbor-cache}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipv6tunnel': {
            'params': ['device', 'ipv6-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-tunnel',
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-tunnel/{ipv6-tunnel}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_iscsi': {
            'params': ['device', 'iscsi'],
            'urls': [
                '/pm/config/device/{device}/global/system/iscsi',
                '/pm/config/device/{device}/global/system/iscsi/{iscsi}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_isfqueueprofile': {
            'params': ['device', 'isf-queue-profile'],
            'urls': [
                '/pm/config/device/{device}/global/system/isf-queue-profile',
                '/pm/config/device/{device}/global/system/isf-queue-profile/{isf-queue-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_linkmonitor': {
            'params': ['device', 'link-monitor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor',
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_linkmonitor_serverlist': {
            'params': ['device', 'link-monitor', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}/server-list',
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}/server-list/{server-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy',
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_guest': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/guest'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_guestvoicesignaling': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/guest-voice-signaling'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_softphone': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/softphone'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_streamingvideo': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/streaming-video'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_videoconferencing': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/video-conferencing'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_videosignaling': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/video-signaling'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_voice': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/voice'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy_voicesignaling': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/voice-signaling'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ltemodem': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/lte-modem'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ltemodem_dataplan': {
            'params': ['data-plan', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/lte-modem/data-plan',
                '/pm/config/device/{device}/global/system/lte-modem/data-plan/{data-plan}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_ltemodem_simswitch': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/lte-modem/sim-switch'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_macaddresstable': {
            'params': ['device', 'mac-address-table', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mac-address-table',
                '/pm/config/device/{device}/vdom/{vdom}/system/mac-address-table/{mac-address-table}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_memmgr': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/mem-mgr'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_mobiletunnel': {
            'params': ['device', 'mobile-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel',
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_mobiletunnel_network': {
            'params': ['device', 'mobile-tunnel', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}/network',
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}/network/{network}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_modem': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/modem'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_nat64': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/nat64'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_nat64_secondaryprefix': {
            'params': ['device', 'secondary-prefix', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/nat64/secondary-prefix',
                '/pm/config/device/{device}/vdom/{vdom}/system/nat64/secondary-prefix/{secondary-prefix}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ndproxy': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/nd-proxy'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_netflow': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_netflow_collectors': {
            'params': ['collectors', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/collectors',
                '/pm/config/device/{device}/global/system/netflow/collectors/{collectors}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_netflow_exclusionfilters': {
            'params': ['device', 'exclusion-filters'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/exclusion-filters',
                '/pm/config/device/{device}/global/system/netflow/exclusion-filters/{exclusion-filters}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_networkvisibility': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/network-visibility'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ngfwsettings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ngfw-settings'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_np6': {
            'params': ['device', 'np6'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6',
                '/pm/config/device/{device}/global/system/np6/{np6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6_fpanomaly': {
            'params': ['device', 'np6'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6/{np6}/fp-anomaly'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6_hpe': {
            'params': ['device', 'np6'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6/{np6}/hpe'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6xlite': {
            'params': ['device', 'np6xlite'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6xlite',
                '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6xlite_fpanomaly': {
            'params': ['device', 'np6xlite'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}/fp-anomaly'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6xlite_hpe': {
            'params': ['device', 'np6xlite'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}/hpe'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_npupost': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-post'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_npupost_portnpumap': {
            'params': ['device', 'port-npu-map'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-post/port-npu-map',
                '/pm/config/device/{device}/global/system/npu-post/port-npu-map/{port-npu-map}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_npusetting_prp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-setting/prp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_npuvlink': {
            'params': ['device', 'npu-vlink'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-vlink',
                '/pm/config/device/{device}/global/system/npu-vlink/{npu-vlink}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ntp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ntp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/ntp/ntpserver',
                '/pm/config/device/{device}/global/system/ntp/ntpserver/{ntpserver}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_passwordpolicy': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/password-policy'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_passwordpolicyguestadmin': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/password-policy-guest-admin'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_pcpserver': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_pcpserver_pools': {
            'params': ['device', 'pools', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server/pools',
                '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server/pools/{pools}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_physicalswitch': {
            'params': ['device', 'physical-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/physical-switch',
                '/pm/config/device/{device}/global/system/physical-switch/{physical-switch}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_pppoeinterface': {
            'params': ['device', 'pppoe-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pppoe-interface',
                '/pm/config/device/{device}/vdom/{vdom}/system/pppoe-interface/{pppoe-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_proberesponse': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/probe-response'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_proxyarp': {
            'params': ['device', 'proxy-arp', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/proxy-arp',
                '/pm/config/device/{device}/vdom/{vdom}/system/proxy-arp/{proxy-arp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ptp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ptp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ptp_serverinterface': {
            'params': ['device', 'server-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/ptp/server-interface',
                '/pm/config/device/{device}/global/system/ptp/server-interface/{server-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_admin': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/admin'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_alertmail': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/alertmail'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_auth': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/auth'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_automation': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/automation'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_custommessage': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/custom-message'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_devicedetectionportal': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/device-detection-portal'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_fortiguardwf': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/fortiguard-wf'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_ftp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/ftp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_http': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/http'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_icap': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/icap'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mail': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mail'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mm1': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mm1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mm3': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mm3'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mm4': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mm4'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mm7': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mm7'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_mms': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/mms'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_nacquar': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/nac-quar'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_nntp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/nntp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_spam': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/spam'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_sslvpn': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/sslvpn'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_trafficquota': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/traffic-quota'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_utm': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/utm'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_replacemsg_webproxy': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg/webproxy'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_saml': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_saml_serviceproviders': {
            'params': ['device', 'service-providers'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers',
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_saml_serviceproviders_assertionattributes': {
            'params': ['assertion-attributes', 'device', 'service-providers'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}/assertion-attributes',
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}/assertion-attributes/{assertion-attributes}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdnvpn': {
            'params': ['device', 'sdn-vpn'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-vpn',
                '/pm/config/device/{device}/global/system/sdn-vpn/{sdn-vpn}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_sdwan': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_duplication': {
            'params': ['device', 'duplication', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/duplication',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/duplication/{duplication}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck': {
            'params': ['device', 'health-check', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck_sla': {
            'params': ['device', 'health-check', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}/sla',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheckfortiguard': {
            'params': ['device', 'health-check-fortiguard', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_sdwan_healthcheckfortiguard_sla': {
            'params': ['device', 'health-check-fortiguard', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}/sla',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}/sla/{sla}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_sdwan_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone',
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone/{zone}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_securityrating_controls': {
            'params': ['controls', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/security-rating/controls',
                '/pm/config/device/{device}/global/system/security-rating/controls/{controls}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_securityrating_settings': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/security-rating/settings'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_sessionhelper': {
            'params': ['device', 'session-helper'],
            'urls': [
                '/pm/config/device/{device}/global/system/session-helper',
                '/pm/config/device/{device}/global/system/session-helper/{session-helper}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sessionttl': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/session-ttl'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sessionttl_port': {
            'params': ['device', 'port', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/session-ttl/port',
                '/pm/config/device/{device}/vdom/{vdom}/system/session-ttl/port/{port}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sflow': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/sflow'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sflow_collectors': {
            'params': ['collectors', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/sflow/collectors',
                '/pm/config/device/{device}/global/system/sflow/collectors/{collectors}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_sittunnel': {
            'params': ['device', 'sit-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sit-tunnel',
                '/pm/config/device/{device}/vdom/{vdom}/system/sit-tunnel/{sit-tunnel}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_smcntp': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/smc-ntp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_smcntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/smc-ntp/ntpserver',
                '/pm/config/device/{device}/global/system/smc-ntp/ntpserver/{ntpserver}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community': {
            'params': ['community', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community',
                '/pm/config/device/{device}/global/system/snmp/community/{community}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts': {
            'params': ['community', 'device', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts',
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts6': {
            'params': ['community', 'device', 'hosts6'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts6',
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_mibview': {
            'params': ['device', 'mib-view'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/mib-view',
                '/pm/config/device/{device}/global/system/snmp/mib-view/{mib-view}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_rmonstat': {
            'params': ['device', 'rmon-stat'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/rmon-stat',
                '/pm/config/device/{device}/global/system/snmp/rmon-stat/{rmon-stat}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_snmp_sysinfo': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/sysinfo'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_user': {
            'params': ['device', 'user'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/user',
                '/pm/config/device/{device}/global/system/snmp/user/{user}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestschedule': {
            'params': ['device', 'speed-test-schedule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-schedule',
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-schedule/{speed-test-schedule}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestserver': {
            'params': ['device', 'speed-test-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server',
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestserver_host': {
            'params': ['device', 'host', 'speed-test-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}/host',
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}/host/{host}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestsetting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/speed-test-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_splitportmode': {
            'params': ['device', 'split-port-mode'],
            'urls': [
                '/pm/config/device/{device}/global/system/global/split-port-mode',
                '/pm/config/device/{device}/global/system/global/split-port-mode/{split-port-mode}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sshconfig': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ssh-config'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_ssoadmin': {
            'params': ['device', 'sso-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-admin',
                '/pm/config/device/{device}/global/system/sso-admin/{sso-admin}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ssoforticloudadmin': {
            'params': ['device', 'sso-forticloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-forticloud-admin',
                '/pm/config/device/{device}/global/system/sso-forticloud-admin/{sso-forticloud-admin}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ssofortigatecloudadmin': {
            'params': ['device', 'sso-fortigate-cloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-fortigate-cloud-admin',
                '/pm/config/device/{device}/global/system/sso-fortigate-cloud-admin/{sso-fortigate-cloud-admin}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer': {
            'params': ['cluster-peer', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer',
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer_sessionsyncfilter': {
            'params': ['cluster-peer', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer_sessionsyncfilter_customservice': {
            'params': ['cluster-peer', 'custom-service', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter/custom-service',
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter/custom-service/{custom-service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_monitorprefix': {
            'params': ['device', 'monitor-prefix'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/monitor-prefix',
                '/pm/config/device/{device}/global/system/standalone-cluster/monitor-prefix/{monitor-prefix}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_storage': {
            'params': ['device', 'storage'],
            'urls': [
                '/pm/config/device/{device}/global/system/storage',
                '/pm/config/device/{device}/global/system/storage/{storage}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_stp': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/stp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_switchinterface': {
            'params': ['device', 'switch-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/switch-interface',
                '/pm/config/device/{device}/global/system/switch-interface/{switch-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_timezone': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/timezone'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_tosbasedpriority': {
            'params': ['device', 'tos-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/tos-based-priority',
                '/pm/config/device/{device}/global/system/tos-based-priority/{tos-based-priority}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdom': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom',
                '/pm/config/device/{device}/global/system/vdom/{vdom}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomdns': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-dns'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomexception': {
            'params': ['device', 'vdom-exception'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-exception',
                '/pm/config/device/{device}/global/system/vdom-exception/{vdom-exception}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomlink': {
            'params': ['device', 'vdom-link'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-link',
                '/pm/config/device/{device}/global/system/vdom-link/{vdom-link}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomnetflow': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomnetflow_collectors': {
            'params': ['collectors', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow/collectors',
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow/collectors/{collectors}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomproperty': {
            'params': ['device', 'vdom-property'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-property',
                '/pm/config/device/{device}/global/system/vdom-property/{vdom-property}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomradiusserver': {
            'params': ['device', 'vdom-radius-server'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-radius-server',
                '/pm/config/device/{device}/global/system/vdom-radius-server/{vdom-radius-server}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomsflow': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-sflow'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomsflow_collectors': {
            'params': ['collectors', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-sflow/collectors',
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-sflow/collectors/{collectors}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_vinalarm': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/vin-alarm'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualswitch': {
            'params': ['device', 'virtual-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/virtual-switch',
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualswitch_port': {
            'params': ['device', 'port', 'virtual-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}/port',
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}/port/{port}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_healthcheck': {
            'params': ['device', 'health-check', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_healthcheck_sla': {
            'params': ['device', 'health-check', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}/sla',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/members',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/members/{members}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/neighbor',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla',
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vneinterface': {
            'params': ['device', 'vdom', 'vne-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vne-interface',
                '/pm/config/device/{device}/vdom/{vdom}/system/vne-interface/{vne-interface}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_vnetunnel': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vne-tunnel'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vpce': {
            'params': ['device', 'vpce'],
            'urls': [
                '/pm/config/device/{device}/global/system/vpce',
                '/pm/config/device/{device}/global/system/vpce/{vpce}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_vxlan': {
            'params': ['device', 'vdom', 'vxlan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vxlan',
                '/pm/config/device/{device}/vdom/{vdom}/system/vxlan/{vxlan}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_wccp': {
            'params': ['device', 'vdom', 'wccp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/wccp',
                '/pm/config/device/{device}/vdom/{vdom}/system/wccp/{wccp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_wireless_apstatus': {
            'params': ['ap-status', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/wireless/ap-status',
                '/pm/config/device/{device}/global/system/wireless/ap-status/{ap-status}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_wireless_settings': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/system/wireless/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone',
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_zone_tagging': {
            'params': ['device', 'tagging', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}/tagging',
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}/tagging/{tagging}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_nacpolicy': {
            'params': ['device', 'nac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy',
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy/{nac-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_quarantine': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_quarantine_targets': {
            'params': ['device', 'targets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets',
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_quarantine_targets_macs': {
            'params': ['device', 'macs', 'targets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}/macs',
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}/macs/{macs}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_scim': {
            'params': ['device', 'scim', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/scim',
                '/pm/config/device/{device}/vdom/{vdom}/user/scim/{scim}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'user_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_setting_authports': {
            'params': ['auth-ports', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/setting/auth-ports',
                '/pm/config/device/{device}/vdom/{vdom}/user/setting/auth-ports/{auth-ports}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'videofilter_youtubekey': {
            'params': ['device', 'vdom', 'youtube-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/youtube-key',
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/youtube-key/{youtube-key}'
            ],
            'v_range': [['7.2.6', '7.2.9']]
        },
        'vpn_certificate_crl': {
            'params': ['crl', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/crl',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/crl/{crl}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_certificate_local': {
            'params': ['device', 'local', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/local',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/local/{local}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_certificate_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_certificate_setting_crlverification': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/setting/crl-verification'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_concentrator': {
            'params': ['concentrator', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/concentrator',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/concentrator/{concentrator}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_forticlient': {
            'params': ['device', 'forticlient', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/forticlient',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/forticlient/{forticlient}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkey': {
            'params': ['device', 'manualkey', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey/{manualkey}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkeyinterface': {
            'params': ['device', 'manualkey-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey-interface',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey-interface/{manualkey-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1': {
            'params': ['device', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv4excluderange': {
            'params': ['device', 'ipv4-exclude-range', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv4-exclude-range',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv6excluderange': {
            'params': ['device', 'ipv6-exclude-range', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv6-exclude-range',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface': {
            'params': ['device', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv4excluderange': {
            'params': ['device', 'ipv4-exclude-range', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv4-exclude-range',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv6excluderange': {
            'params': ['device', 'ipv6-exclude-range', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv6-exclude-range',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2': {
            'params': ['device', 'phase2', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2/{phase2}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2interface': {
            'params': ['device', 'phase2-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{phase2-interface}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_kmipserver': {
            'params': ['device', 'kmip-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'vpn_kmipserver_serverlist': {
            'params': ['device', 'kmip-server', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}/server-list',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}/server-list/{server-list}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'vpn_l2tp': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/l2tp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_forticlientaccess': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/forticlient-access'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_forticlientaccess_authgroups': {
            'params': ['auth-groups', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/forticlient-access/auth-groups',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/forticlient-access/auth-groups/{auth-groups}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays': {
            'params': ['device', 'overlays', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays_subnets': {
            'params': ['device', 'overlays', 'subnets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}/subnets',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}/subnets/{subnets}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_pptp': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/pptp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_qkd': {
            'params': ['device', 'qkd', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/qkd',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/qkd/{qkd}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'vpn_ssl_client': {
            'params': ['client', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/client',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/client/{client}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ssl_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnsslweb_userbookmark': {
            'params': ['device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks_formdata': {
            'params': ['bookmarks', 'device', 'form-data', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}/form-data',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark': {
            'params': ['device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks_formdata': {
            'params': ['bookmarks', 'device', 'form-data', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}/form-data',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_cacheservice': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_cacheservice_dstpeer': {
            'params': ['device', 'dst-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/dst-peer',
                '/pm/config/device/{device}/global/wanopt/cache-service/dst-peer/{dst-peer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_cacheservice_srcpeer': {
            'params': ['device', 'src-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/src-peer',
                '/pm/config/device/{device}/global/wanopt/cache-service/src-peer/{src-peer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule': {
            'params': ['content-delivery-network-rule', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule',
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules': {
            'params': ['content-delivery-network-rule', 'device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules',
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_contentid': {
            'params': ['content-delivery-network-rule', 'device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/content-id'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_matchentries': {
            'params': ['content-delivery-network-rule', 'device', 'match-entries', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/match-entries',
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/match-entries/{match-en'
                'tries}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_skipentries': {
            'params': ['content-delivery-network-rule', 'device', 'rules', 'skip-entries'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/skip-entries',
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/skip-entries/{skip-entr'
                'ies}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_remotestorage': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/remote-storage'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/settings'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_webcache': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/webcache'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_fortiguard': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/webfilter/fortiguard'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_ftgdlocalrisk': {
            'params': ['device', 'ftgd-local-risk', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-local-risk',
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-local-risk/{ftgd-local-risk}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'webfilter_ftgdrisklevel': {
            'params': ['device', 'ftgd-risk-level', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-risk-level',
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-risk-level/{ftgd-risk-level}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'webfilter_ipsurlfiltercachesetting': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/webfilter/ips-urlfilter-cache-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_ipsurlfiltersetting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ips-urlfilter-setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_ipsurlfiltersetting6': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ips-urlfilter-setting6'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_override': {
            'params': ['device', 'override', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/override',
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/override/{override}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_searchengine': {
            'params': ['device', 'search-engine', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/search-engine',
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/search-engine/{search-engine}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_debugurl': {
            'params': ['debug-url', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/debug-url',
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/debug-url/{debug-url}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_explicit': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_explicit_pacpolicy': {
            'params': ['device', 'pac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit/pac-policy',
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit/pac-policy/{pac-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_fastfallback': {
            'params': ['device', 'fast-fallback', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/fast-fallback',
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/fast-fallback/{fast-fallback}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'webproxy_global': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_urlmatch': {
            'params': ['device', 'url-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-match',
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-match/{url-match}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist': {
            'params': ['access-control-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv4-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv6-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile': {
            'params': ['apcfg-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile_commandlist': {
            'params': ['apcfg-profile', 'command-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apstatus': {
            'params': ['ap-status', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ap-status',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ap-status/{ap-status}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_arrpprofile': {
            'params': ['arrp-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/arrp-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bleprofile': {
            'params': ['ble-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile/{ble-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile': {
            'params': ['bonjour-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile_policylist': {
            'params': ['bonjour-profile', 'device', 'policy-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_global': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/global'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular': {
            'params': ['anqp-3gpp-cellular', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular_mccmnclist': {
            'params': ['anqp-3gpp-cellular', 'device', 'mcc-mnc-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpipaddresstype': {
            'params': ['anqp-ip-address-type', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-ip-address-type',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm': {
            'params': ['anqp-nai-realm', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist': {
            'params': ['anqp-nai-realm', 'device', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': ['anqp-nai-realm', 'device', 'eap-method', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': ['anqp-nai-realm', 'auth-param', 'device', 'eap-method', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}/auth-param',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}/auth-param/{auth-param}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnetworkauthtype': {
            'params': ['anqp-network-auth-type', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-network-auth-type',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqproamingconsortium': {
            'params': ['anqp-roaming-consortium', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqproamingconsortium_oilist': {
            'params': ['anqp-roaming-consortium', 'device', 'oi-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenuename': {
            'params': ['anqp-venue-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenuename_valuelist': {
            'params': ['anqp-venue-name', 'device', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenueurl': {
            'params': ['anqp-venue-url', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenueurl_valuelist': {
            'params': ['anqp-venue-url', 'device', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge': {
            'params': ['device', 'h2qp-advice-of-charge', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist': {
            'params': ['aoc-list', 'device', 'h2qp-advice-of-charge', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': ['aoc-list', 'device', 'h2qp-advice-of-charge', 'plan-info', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-'
                'info',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-'
                'info/{plan-info}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpconncapability': {
            'params': ['device', 'h2qp-conn-capability', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-conn-capability',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpoperatorname': {
            'params': ['device', 'h2qp-operator-name', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpoperatorname_valuelist': {
            'params': ['device', 'h2qp-operator-name', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider': {
            'params': ['device', 'h2qp-osu-provider', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_friendlyname': {
            'params': ['device', 'friendly-name', 'h2qp-osu-provider', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_servicedescription': {
            'params': ['device', 'h2qp-osu-provider', 'service-description', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-desc'
                'ription}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai': {
            'params': ['device', 'h2qp-osu-provider-nai', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai_nailist': {
            'params': ['device', 'h2qp-osu-provider-nai', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qptermsandconditions': {
            'params': ['device', 'h2qp-terms-and-conditions', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-terms-and-conditions',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpwanmetric': {
            'params': ['device', 'h2qp-wan-metric', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-wan-metric',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_hsprofile': {
            'params': ['device', 'hs-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/hs-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon': {
            'params': ['device', 'icon', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon_iconlist': {
            'params': ['device', 'icon', 'icon-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}/icon-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap': {
            'params': ['device', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscpexcept': {
            'params': ['device', 'dscp-except', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscprange': {
            'params': ['device', 'dscp-range', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_intercontroller': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/inter-controller'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_intercontroller_intercontrollerpeer': {
            'params': ['device', 'inter-controller-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/inter-controller/inter-controller-peer',
                '/pm/config/device/{device}/global/wireless-controller/inter-controller/inter-controller-peer/{inter-controller-peer}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_log': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/log'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile': {
            'params': ['device', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup': {
            'params': ['device', 'mpsk-group', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup_mpskkey': {
            'params': ['device', 'mpsk-group', 'mpsk-key', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_nacprofile': {
            'params': ['device', 'nac-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/nac-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/nac-profile/{nac-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_qosprofile': {
            'params': ['device', 'qos-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/qos-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/qos-profile/{qos-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_region': {
            'params': ['device', 'region', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/region',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/region/{region}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_setting': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_setting_offendingssid': {
            'params': ['device', 'offending-ssid', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting/offending-ssid',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting/offending-ssid/{offending-ssid}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_community': {
            'params': ['community', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_community_hosts': {
            'params': ['community', 'device', 'hosts', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}/hosts',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}/hosts/{hosts}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_user': {
            'params': ['device', 'user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/user',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/user/{user}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_ssidpolicy': {
            'params': ['device', 'ssid-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ssid-policy',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_syslogprofile': {
            'params': ['device', 'syslog-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/syslog-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_timers': {
            'params': ['device'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/timers'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_utmprofile': {
            'params': ['device', 'utm-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/utm-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/utm-profile/{utm-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap': {
            'params': ['device', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_dynamicmapping': {
            'params': ['device', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/dynamic_mapping'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_macfilterlist': {
            'params': ['device', 'mac-filter-list', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mac-filter-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_mpskkey': {
            'params': ['device', 'mpsk-key', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mpsk-key',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_portalmessageoverrides': {
            'params': ['device', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/portal-message-overrides'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_vlanname': {
            'params': ['device', 'vap', 'vdom', 'vlan-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_vlanpool': {
            'params': ['device', 'vap', 'vdom', 'vlan-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-pool',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vapgroup': {
            'params': ['device', 'vap-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap-group',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap-group/{vap-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wagprofile': {
            'params': ['device', 'vdom', 'wag-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wag-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wag-profile/{wag-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_widsprofile': {
            'params': ['device', 'vdom', 'wids-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wids-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wids-profile/{wids-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_lan': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/lan'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_radio1': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/radio-1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_radio2': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/radio-2'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_radio3': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/radio-3'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_radio4': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/radio-4'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_splittunnelingacl': {
            'params': ['device', 'split-tunneling-acl', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/split-tunneling-acl',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpgroup': {
            'params': ['device', 'vdom', 'wtp-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-group',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-group/{wtp-group}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_denymaclist': {
            'params': ['deny-mac-list', 'device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_eslsesdongle': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_lan': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/lan'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_lbs': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/lbs'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_platform': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/platform'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_radio1': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/radio-1'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_radio2': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/radio-2'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_radio3': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/radio-3'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_radio4': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/radio-4'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_splittunnelingacl': {
            'params': ['device', 'split-tunneling-acl', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl',
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ztna_reverseconnector': {
            'params': ['device', 'reverse-connector', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/reverse-connector',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/reverse-connector/{reverse-connector}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_trafficforwardproxy': {
            'params': ['device', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxy_quic': {
            'params': ['device', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/quic'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxy_sslciphersuites': {
            'params': ['device', 'ssl-cipher-suites', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-cipher-suites',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxy_sslserverciphersuites': {
            'params': ['device', 'ssl-server-cipher-suites', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-server-cipher-suites',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-server-cipher-suites/{ssl-server-cipher-suites'
                '}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxyreverseservice': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy-reverse-service'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxyreverseservice_remoteservers': {
            'params': ['device', 'remote-servers', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy-reverse-service/remote-servers',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy-reverse-service/remote-servers/{remote-servers}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'ztna_webportal': {
            'params': ['device', 'vdom', 'web-portal'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal/{web-portal}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webportalbookmark': {
            'params': ['device', 'vdom', 'web-portal-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webportalbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'vdom', 'web-portal-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}/bookmarks',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}/bookmarks/{bookmarks}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy': {
            'params': ['device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway': {
            'params': ['api-gateway', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6': {
            'params': ['api-gateway6', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_quic': {
            'params': ['api-gateway6', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/quic'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_realservers': {
            'params': ['api-gateway6', 'device', 'realservers', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/realservers',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_sslciphersuites': {
            'params': ['api-gateway6', 'device', 'ssl-cipher-suites', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_quic': {
            'params': ['api-gateway', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/quic'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_realservers': {
            'params': ['api-gateway', 'device', 'realservers', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_sslciphersuites': {
            'params': ['api-gateway', 'device', 'ssl-cipher-suites', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites',
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'facts': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(facts_metadata.keys())
                },
                'fields': {'type': 'list', 'elements': 'raw'},
                'filter': {'type': 'list', 'elements': 'raw'},
                'option': {'type': 'raw'},
                'sortings': {'type': 'list', 'elements': 'raw'},
                'params': {'type': 'dict'},
                'extra_params': {'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('facts', facts_metadata, None, None, None, module, connection)
    fmgd.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
