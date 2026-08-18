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
module: fmgd_system_replacemsggroup
short_description: Configure replacement message groups.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  system_replacemsggroup:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      admin:
        type: list
        elements: dict
        description: Admin.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      alertmail:
        type: list
        elements: dict
        description: Alertmail.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          id:
            type: int
            description: Id.
      auth:
        type: list
        elements: dict
        description: Auth.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      automation:
        type: list
        elements: dict
        description: Automation.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      comment:
        type: str
        description: Comment.
      custom_message:
        aliases: ['custom-message']
        type: list
        elements: dict
        description: Custom message.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      fortiguard_wf:
        aliases: ['fortiguard-wf']
        type: list
        elements: dict
        description: Fortiguard wf.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      ftp:
        type: list
        elements: dict
        description: Ftp.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      group_type:
        aliases: ['group-type']
        type: str
        description: Group type.
        choices: ['default', 'utm', 'auth', 'ec']
      http:
        type: list
        elements: dict
        description: Http.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      icap:
        type: list
        elements: dict
        description: Icap.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      mail:
        type: list
        elements: dict
        description: Mail.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      nac_quar:
        aliases: ['nac-quar']
        type: list
        elements: dict
        description: Nac quar.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          id:
            type: int
            description: Id.
      name:
        type: str
        description: Group name.
        required: true
      spam:
        type: list
        elements: dict
        description: Spam.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      traffic_quota:
        aliases: ['traffic-quota']
        type: list
        elements: dict
        description: Traffic quota.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      utm:
        type: list
        elements: dict
        description: Utm.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      webproxy:
        type: list
        elements: dict
        description: Webproxy.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      sslvpn:
        type: list
        elements: dict
        description: Sslvpn.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      device_detection_portal:
        aliases: ['device-detection-portal']
        type: list
        elements: dict
        description: Device detection portal.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      nntp:
        type: list
        elements: dict
        description: Nntp.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      mms:
        type: list
        elements: dict
        description: Mms.
        suboptions:
          buffer:
            type: str
            description: Message string.
          charset:
            type: str
            description: Character encoding used for replacement message
            choices: ['us-ascii', 'utf-8']
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          image:
            type: list
            elements: str
            description: Message string.
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      mm1:
        type: list
        elements: dict
        description: Mm1.
        suboptions:
          add_smil:
            aliases: ['add-smil']
            type: str
            description: Add message encapsulation
            choices: ['disable', 'enable']
          charset:
            type: str
            description: Character encoding used for replacement message
            choices: ['us-ascii', 'utf-8']
          class:
            type: str
            description: Message class
            choices: ['personal', 'advertisement', 'information', 'automatic', 'not-included']
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          from:
            type: str
            description: From address
          from_sender:
            aliases: ['from-sender']
            type: str
            description: Notification message sent from recipient
            choices: ['disable', 'enable']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          image:
            type: list
            elements: str
            description: Message string.
          fmgr_message:
            type: str
            description: Message text
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          priority:
            type: str
            description: Message priority
            choices: ['low', 'normal', 'high', 'not-included']
          rsp_status:
            aliases: ['rsp-status']
            type: str
            description: Response status code
            choices: ['ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt',
                      'err-snd-addr-unresolv', 'err-msg-not-found', 'err-net-prob',
                      'err-content-not-accept', 'err-unsupp-msg']
          rsp_text:
            aliases: ['rsp-text']
            type: str
            description: Response text
          sender_visibility:
            aliases: ['sender-visibility']
            type: str
            description: Sender visibility
            choices: ['hide', 'show', 'not-specified']
          smil_part:
            aliases: ['smil-part']
            type: str
            description: Message encapsulation text
          subject:
            type: str
            description: Subject text string
      mm7:
        type: list
        elements: dict
        description: Mm7.
        suboptions:
          add_smil:
            aliases: ['add-smil']
            type: str
            description: Add message encapsulation
            choices: ['disable', 'enable']
          addr_type:
            aliases: ['addr-type']
            type: str
            description: From address type
            choices: ['rfc2822-addr', 'number', 'short-code']
          allow_content_adaptation:
            aliases: ['allow-content-adaptation']
            type: str
            description: Allow content adaptations
            choices: ['disable', 'enable']
          charset:
            type: str
            description: Character encoding used for replacement message
            choices: ['us-ascii', 'utf-8']
          class:
            type: str
            description: Message class
            choices: ['personal', 'advertisement', 'informational', 'auto', 'not-included']
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          from:
            type: str
            description: From address
          from_sender:
            aliases: ['from-sender']
            type: str
            description: Notification message sent from recipient
            choices: ['disable', 'enable']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          image:
            type: list
            elements: str
            description: Message string.
          fmgr_message:
            type: str
            description: Message text
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          priority:
            type: str
            description: Message priority
            choices: ['low', 'normal', 'high', 'not-included']
          rsp_status:
            aliases: ['rsp-status']
            type: str
            description: Response status
            choices: ['success', 'partial-success', 'client-err', 'oper-restrict', 'addr-err',
                      'addr-not-found', 'content-refused', 'msg-id-not-found',
                      'link-id-not-found', 'msg-fmt-corrupt', 'app-id-not-found',
                      'repl-app-id-not-found', 'srv-err', 'not-possible', 'msg-rejected',
                      'multiple-addr-not-supp', 'app-addr-not-supp', 'gen-service-err',
                      'improper-ident', 'unsupp-ver', 'unsupp-oper', 'validation-err',
                      'service-err', 'service-unavail', 'service-denied', 'app-denied']
          smil_part:
            aliases: ['smil-part']
            type: str
            description: Message encapsulation text
          subject:
            type: str
            description: Subject text string
      mm4:
        type: list
        elements: dict
        description: Mm4.
        suboptions:
          add_smil:
            aliases: ['add-smil']
            type: str
            description: Add message encapsulation
            choices: ['disable', 'enable']
          charset:
            type: str
            description: Character encoding used for replacement message
            choices: ['us-ascii', 'utf-8']
          class:
            type: str
            description: Message class
            choices: ['personal', 'advertisement', 'informational', 'auto', 'not-included']
          domain:
            type: str
            description: From address domain
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          from:
            type: str
            description: From address
          from_sender:
            aliases: ['from-sender']
            type: str
            description: Notification message sent from recipient
            choices: ['disable', 'enable']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          image:
            type: list
            elements: str
            description: Message string.
          fmgr_message:
            type: str
            description: Message text
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          priority:
            type: str
            description: Message priority
            choices: ['low', 'normal', 'high', 'not-included']
          rsp_status:
            aliases: ['rsp-status']
            type: str
            description: Response status
            choices: ['ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt',
                      'err-snd-addr-unresolv', 'err-net-prob', 'err-content-not-accept',
                      'err-unsupp-msg']
          smil_part:
            aliases: ['smil-part']
            type: str
            description: Message encapsulation text
          subject:
            type: str
            description: Subject text string
      mm3:
        type: list
        elements: dict
        description: Mm3.
        suboptions:
          add_html:
            aliases: ['add-html']
            type: str
            description: Add message encapsulation
            choices: ['disable', 'enable']
          charset:
            type: str
            description: Character encoding used for replacement message
            choices: ['us-ascii', 'utf-8']
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html', 'wml']
          from:
            type: str
            description: From address
          from_sender:
            aliases: ['from-sender']
            type: str
            description: Notification message sent from recipient
            choices: ['disable', 'enable']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          html_part:
            aliases: ['html-part']
            type: str
            description: Message encapsulation text
          image:
            type: list
            elements: str
            description: Message string.
          fmgr_message:
            type: str
            description: Message text
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
          priority:
            type: str
            description: Message priority
            choices: ['low', 'normal', 'high', 'not-included']
          subject:
            type: str
            description: Subject text string
      ec:
        type: list
        elements: dict
        description: Ec.
        suboptions:
          buffer:
            type: str
            description: Message string.
          format:
            type: str
            description: Format flag.
            choices: ['none', 'text', 'html']
          header:
            type: str
            description: Header flag.
            choices: ['none', 'http', '8bit']
          msg_type:
            aliases: ['msg-type']
            type: str
            description: Message type.
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure replacement message groups.
      fortinet.fmgdevice.fmgd_system_replacemsggroup:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_replacemsggroup:
          name: "your value" # Required variable, string
          # admin:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # alertmail:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          #     id: <integer>
          # auth:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # automation:
          #   - buffer: <string>
          #     format: <value in [none, text, html]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # comment: <string>
          # custom_message:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # fortiguard_wf:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # ftp:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # group_type: <value in [default, utm, auth, ...]>
          # http:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # icap:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # mail:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # nac_quar:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          #     id: <integer>
          # spam:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # traffic_quota:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # utm:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # webproxy:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # sslvpn:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # device_detection_portal:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # nntp:
          #   - buffer: <string>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # mms:
          #   - buffer: <string>
          #     charset: <value in [us-ascii, utf-8]>
          #     format: <value in [none, text, html, ...]>
          #     header: <value in [none, http, 8bit]>
          #     image: <list or string>
          #     msg_type: <string>
          # mm1:
          #   - add_smil: <value in [disable, enable]>
          #     charset: <value in [us-ascii, utf-8]>
          #     class: <value in [personal, advertisement, information, ...]>
          #     format: <value in [none, text, html, ...]>
          #     from: <string>
          #     from_sender: <value in [disable, enable]>
          #     header: <value in [none, http, 8bit]>
          #     image: <list or string>
          #     fmgr_message: <string>
          #     msg_type: <string>
          #     priority: <value in [low, normal, high, ...]>
          #     rsp_status: <value in [ok, err-unspecified, err-srv-denied, ...]>
          #     rsp_text: <string>
          #     sender_visibility: <value in [hide, show, not-specified]>
          #     smil_part: <string>
          #     subject: <string>
          # mm7:
          #   - add_smil: <value in [disable, enable]>
          #     addr_type: <value in [rfc2822-addr, number, short-code]>
          #     allow_content_adaptation: <value in [disable, enable]>
          #     charset: <value in [us-ascii, utf-8]>
          #     class: <value in [personal, advertisement, informational, ...]>
          #     format: <value in [none, text, html, ...]>
          #     from: <string>
          #     from_sender: <value in [disable, enable]>
          #     header: <value in [none, http, 8bit]>
          #     image: <list or string>
          #     fmgr_message: <string>
          #     msg_type: <string>
          #     priority: <value in [low, normal, high, ...]>
          #     rsp_status: <value in [success, partial-success, client-err, ...]>
          #     smil_part: <string>
          #     subject: <string>
          # mm4:
          #   - add_smil: <value in [disable, enable]>
          #     charset: <value in [us-ascii, utf-8]>
          #     class: <value in [personal, advertisement, informational, ...]>
          #     domain: <string>
          #     format: <value in [none, text, html, ...]>
          #     from: <string>
          #     from_sender: <value in [disable, enable]>
          #     header: <value in [none, http, 8bit]>
          #     image: <list or string>
          #     fmgr_message: <string>
          #     msg_type: <string>
          #     priority: <value in [low, normal, high, ...]>
          #     rsp_status: <value in [ok, err-unspecified, err-srv-denied, ...]>
          #     smil_part: <string>
          #     subject: <string>
          # mm3:
          #   - add_html: <value in [disable, enable]>
          #     charset: <value in [us-ascii, utf-8]>
          #     format: <value in [none, text, html, ...]>
          #     from: <string>
          #     from_sender: <value in [disable, enable]>
          #     header: <value in [none, http, 8bit]>
          #     html_part: <string>
          #     image: <list or string>
          #     fmgr_message: <string>
          #     msg_type: <string>
          #     priority: <value in [low, normal, high, ...]>
          #     subject: <string>
          # ec:
          #   - buffer: <string>
          #     format: <value in [none, text, html]>
          #     header: <value in [none, http, 8bit]>
          #     msg_type: <string>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/replacemsg-group'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_replacemsggroup': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'admin': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'alertmail': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'auth': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'automation': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'custom-message': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fortiguard-wf': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ftp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'utm', 'auth', 'ec'], 'type': 'str'},
                'http': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'icap': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mail': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'nac-quar': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'spam': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'traffic-quota': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'utm': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'webproxy': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'sslvpn': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'device-detection-portal': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'nntp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mms': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'charset': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm1': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': ['personal', 'advertisement', 'information', 'automatic', 'not-included'],
                            'type': 'str'
                        },
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'from-sender': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                        'fmgr_message': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'priority': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': [
                                'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-msg-not-found',
                                'err-net-prob', 'err-content-not-accept', 'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'rsp-text': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'sender-visibility': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['hide', 'show', 'not-specified'], 'type': 'str'},
                        'smil-part': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'subject': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm7': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'addr-type': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['rfc2822-addr', 'number', 'short-code'], 'type': 'str'},
                        'allow-content-adaptation': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                            'type': 'str'
                        },
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'from-sender': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                        'fmgr_message': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'priority': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': [
                                'success', 'partial-success', 'client-err', 'oper-restrict', 'addr-err', 'addr-not-found', 'content-refused',
                                'msg-id-not-found', 'link-id-not-found', 'msg-fmt-corrupt', 'app-id-not-found', 'repl-app-id-not-found', 'srv-err',
                                'not-possible', 'msg-rejected', 'multiple-addr-not-supp', 'app-addr-not-supp', 'gen-service-err', 'improper-ident',
                                'unsupp-ver', 'unsupp-oper', 'validation-err', 'service-err', 'service-unavail', 'service-denied', 'app-denied'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'subject': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm4': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                            'type': 'str'
                        },
                        'domain': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'from-sender': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                        'fmgr_message': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'priority': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'choices': [
                                'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-net-prob',
                                'err-content-not-accept', 'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'subject': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm3': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'add-html': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'from-sender': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'html-part': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'image': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                        'fmgr_message': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'priority': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'subject': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ec': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                        'format': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'text', 'html'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
