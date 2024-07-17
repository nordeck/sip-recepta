"""
This script is tested on Debian 12 Bookworm.
Required packages: python3 python3-requests

Enable python3 in /etc/freeswitch/autoload_configs/modules.conf.xml

  <load module="mod_python3"/>

Put this file into /usr/local/lib/python3.11/dist-packages/nordeck/

Create /usr/local/lib/python3.11/dist-packages/nordeck/__init__.py
  touch /usr/local/lib/python3.11/dist-packages/nordeck/__init__.py

Add /etc/freeswitch/dialplan/public/98_public_siprecepta_dialplan.xml

Add /etc/freeswitch/dialplan/default/99_default_siprecepta_dialplan.xml

Add SIP-Jibri's conference mapper URI in /etc/freeswitch/vars.xml
Add component_selector_url
Add component_selector_verify if its certificate is self-signed
Add component_selector_token if PROTECTED_SIGNAL_API is set in component-selector

  <X-PRE-PROCESS cmd="set" data="conference_mapper_sipjibri_uri=https://domain/path?pin={pin}"/>
  <X-PRE-PROCESS cmd="set" data="component_selector_url=https://domain/path"/>
  <X-PRE-PROCESS cmd="set" data="component_selector_verify=false"/>
  <X-PRE-PROCESS cmd="set" data="component_selector_token=eyJhbG..."/>

To generate component_selector_token:
  PRIVATE_KEY_FILE="/path/to/signal.key"

  HEADER=$(echo -n '{"alg":"RS256","typ":"JWT","kid":"jitsi/signal"}' | \
    base64 | tr '+/' '-_' | tr -d '=\n')
  PAYLOAD=$(echo -n '{"iss":"signal","aud":"jitsi-component-selector"}' | \
    base64 | tr '+/' '-_' | tr -d '=\n')
  SIGN=$(echo -n "$HEADER.$PAYLOAD" | \
    openssl dgst -sha256 -binary -sign $PRIVATE_KEY_FILE | \
    openssl enc -base64 | tr '+/' '-_' | tr -d '=\n')

  TOKEN="$HEADER.$PAYLOAD.$SIGN"

Add "siprecepta" folder in /etc/freeswitch/directory/default.xml

  <groups>
    <group name="default">
      <users>
        <X-PRE-PROCESS cmd="include" data="default/*.xml"/>
        <X-PRE-PROCESS cmd="include" data="/tmp/siprecepta/*.xml"/>
      </users>
    </group>
  </groups>

Restart FreeSwitch
  systemctl restart freeswitch.service
"""

from datetime import datetime, timedelta
from glob import glob
from os import makedirs, remove
from os.path import getmtime
from random import randint
from time import time
import json
import requests
import freeswitch

PIN_MAX_LENGTH = 9
ALLOWED_ATTEMPTS = 3
REQUESTS_TIMEOUT = 10
PIN_INPUT_TIMEOUT = 20

DISPLAYNAME = "Cisco"
EXTENSION_EXPIRE_MINUTES = 60
USER_DIR = "/tmp/siprecepta"
USER_TPL = """
<include>
  <user id="{sipUser}">
    <params>
      <param name="password" value="{sipPass}"/>
    </params>
    <variables>
      <variable name="toll_allow" value="local"/>
      <variable name="user_context" value="default"/>
    </variables>
  </user>
</include>
"""

# pylint: disable=bare-except

# ------------------------------------------------------------------------------
def create_extension(api, session, sip_domain, sip_user, sip_pass):
    """
    Create a temporary SIP extension only for this session.
    """

    try:
        # Create the extension config file
        makedirs(USER_DIR, exist_ok=True)
        xml = USER_TPL.format(
            sipDomain=sip_domain,
            sipUser=sip_user,
            sipPass=sip_pass,
        )
        path = f"{USER_DIR}/siprecepta_{sip_user}.xml"
        with open(path, "w", encoding="utf-8") as file:
            file.write(xml)

        # Reload config to activate the new extension
        reply = api.executeString("reloadxml")
        freeswitch.consoleLog("info", f"reload result: {reply}\n")
        session.sleep(500)

        return True
    except:
        pass

    return False

# ------------------------------------------------------------------------------
def query_meeting(pin):
    """
    Get the meeting data from API service by using PIN.
    """

    # Dont continue if there is no pin
    if pin == "":
        return {}

    try:
        api = freeswitch.API()
        uri = api.executeString("global_getvar conference_mapper_sipjibri_uri")
        uri = uri.format(pin=pin)
        res = requests.get(uri, timeout=REQUESTS_TIMEOUT)
        jdata = res.json()
        room = jdata.get("room")

        freeswitch.consoleLog("info", f"SIP-Jibri Conference: {room}")

        return jdata
    except:
        pass

    return {}

# ------------------------------------------------------------------------------
def request_sipjibri(sip_domain, sip_port, sip_user, sip_pass, meeting):
    """
    Send a request to component-selector to activate a SIP-Jibri instance for
    this session.
    """

    try:
        headers = {
            "Content-Type": "application/json",
        }

        if meeting.get("token"):
            room = f"{meeting.get('room')}?jwt={meeting.get('token')}"
        else:
            room = meeting.get("room")

        # contact is a private IP address to force FreeSwitch to overwrite it
        data = {
            "callParams": {
                "callUrlInfo": {
                    "baseUrl": meeting.get("host"),
                    "callName": room
                }
            },
            "componentParams": {
                "type": "SIP-JIBRI",
                "region": "default-region",
                "environment": "default-env"
            },
            "metadata": {
                "sipClientParams": {
                    "userName": f"{sip_user}@{sip_domain}:{sip_port}",
                    "password": f"{sip_pass}",
                    "contact": f"<sip:{sip_user}@192.168.1.1>",
                    "sipAddress": "sip:jibri@127.0.0.1",
                    "displayName": DISPLAYNAME,
                    "autoAnswer": True,
                    "autoAnswerTimer": 30
                }
            }
        }

        api = freeswitch.API()
        url = api.executeString("global_getvar component_selector_url")
        freeswitch.consoleLog("info", f"component_selector_url: {url}")
        if not url:
            return False

        verify = api.executeString("global_getvar component_selector_verify")
        freeswitch.consoleLog("info", f"component_selector_verify: {verify}")
        if not verify:
            verify = True
        elif verify.lower() == "false":
            verify = False
        else:
            verify = True
        freeswitch.consoleLog("info", f"generated verify: {verify}")

        token = api.executeString("global_getvar component_selector_token")
        freeswitch.consoleLog("debug", f"component_selector_token: {token}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Post the request
        json_data = json.dumps(data)
        freeswitch.consoleLog("debug", f"post data: {json_data}")
        res= requests.post(
            url,
            headers=headers,
            data=json_data,
            timeout=10,
            verify=verify,
        )
        json_res = res.json()
        freeswitch.consoleLog("info", f"post result: {json_res}")

        # If componentKey exists in response, this means that SIP-Jibri was
        # activated.
        if json_res.get("componentKey"):
            return True
    except:
        pass

    return False

# ------------------------------------------------------------------------------
def get_meeting(session):
    """
    Ask the caller for PIN and get the meeting data from API service by using
    this PIN.
    """

    try:
        # Ask for PIN
        session.streamFile("conference/conf-pin.wav")

        i = 1
        while True:
            # get PIN
            pin = session.getDigits(PIN_MAX_LENGTH, "#", PIN_INPUT_TIMEOUT * 1000)
            freeswitch.consoleLog("debug", f"PIN NUMBER {i}: {pin}")

            # Completed if there is a valid reply from API service for this PIN
            meeting = query_meeting(pin)
            if meeting:
                return meeting

            # Dont continue if there are many failed attempts.
            i += 1
            if i > ALLOWED_ATTEMPTS:
                break

            # Ask again after the failed attempt.
            if pin:
                session.streamFile("conference/conf-bad-pin.wav")
            else:
                session.streamFile("conference/conf-pin.wav")
    except:
        pass

    return {}

# ------------------------------------------------------------------------------
def remove_expired_extensions():
    """
    Remove expired SipRecepta extensions.
    This is a rutin cleanup process, not directly related with ongoing session.
    """

    try:
        expire_at = datetime.now() - timedelta(minutes=EXTENSION_EXPIRE_MINUTES)

        # Trace SipRecepta extension folder and remove expired config files.
        for file in glob(f"{USER_DIR}/siprecepta_*.xml"):
            if getmtime(file) < expire_at.timestamp():
                remove(file)
    except:
        pass

# ------------------------------------------------------------------------------
def invite_sipjibri(session, meeting):
    """
     - Create a temporary SIP extension only for this session
     - Invite SIP-Jibri by using this extension
     - Return the extension number if everything went right
    """

    try:
        api = freeswitch.API()

        # Generate extension data
        sip_domain = api.executeString("global_getvar domain")
        sip_port = api.executeString("global_getvar internal_sip_port")
        sip_user = str(int(time() * 1000))[-9:]
        sip_pass = randint(10**8, 10**9 - 1)

        # Create the extension
        if not create_extension(api, session, sip_domain, sip_user, sip_pass):
            return None

        # Send a request to component-selector to activate a SIP-Jibri instance
        okay = request_sipjibri(
            sip_domain,
            sip_port,
            sip_user,
            sip_pass,
            meeting,
        )
        if not okay:
            return None

        return sip_user
    except:
        return None

# ------------------------------------------------------------------------------
def handler(session, _args):
    """
    SipRecepta handler. This is the main entrypoint.
    """

    try:
        freeswitch.consoleLog("info", "SipRecepta handler\n")

        # Answer the call
        session.answer()
        session.sleep(2000)

        # Get the meeting info. Cancel the session if no meeting info.
        # The conference PIN number will be asked during this process.
        meeting = get_meeting(session)
        if not meeting:
            session.hangup()
            return

        # Remove expired extensions (rutin cleanup process)
        remove_expired_extensions()

        # Invite SIP-Jibri to the meeting
        extension = invite_sipjibri(session, meeting)
        freeswitch.consoleLog(
            "info",
            f"SipRecepta extension: {extension}\n"
        )
        if not extension:
            session.hangup()
            return

        # Request is accepted
        freeswitch.consoleLog("info", "the conference request is accepted\n")
        session.streamFile("conference/conf-conference_will_start_shortly.wav")
        session.sleep(3000)

        # Transfer the call to SIP-Jibri extension
        session.transfer(extension, "XML", "default")
    except:
        pass
