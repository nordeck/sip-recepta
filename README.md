# SipRecepta

Incoming SIP call router for `SIP-Jibri`.

This repository contains scripts, files and documentation to convert
`FreeSwitch` into a router for incoming SIP calls for `SIP-Jibri`. Assumed that
following services are already installed and configured correctly:

- `Jitsi`
- `Jitsi-Component-Selector`
- `SIP-Jibri` with `Jitsi-Component-Sidecar`
- `FreeSwitch`

## Adding SipRecepta

`SipRecepta` is a plugin for `FreeSwitch` to route incoming SIP calls to
`SIP-Jibri`. The following steps are tested in `Debian 12 Bookworm`. Assumed
that `FreeSwitch` already installed and running on this server.

### Install additional packages

```bash
apt-get update
apt-get install python3 python3-requests
```

### Enable Python3 in FreeSwitch

In _/etc/freeswitch/autoload_configs/modules.conf.xml_:

```xml
<load module="mod_python3"/>
```

### Install SipRecepta

```bash
cd /usr/local/lib/python3.11/dist-packages
mkdir nordeck
cd nordeck
touch __init__.py
wget https://raw.githubusercontent.com/nordeck/sip-recepta/main/files/siprecepta.py
```

### DialPlan

```bash
cd /etc/freeswitch/dialplan/public
wget https://raw.githubusercontent.com/nordeck/sip-recepta/main/files/98_public_siprecepta_dialplan.xml

cd /etc/freeswitch/dialplan/default
wget https://raw.githubusercontent.com/nordeck/sip-recepta/main/files/99_default_siprecepta_dialplan.xml
```

### Directory

Put `siprecepta` folder into _/etc/freeswitch/directory/default.xml_

```xml
<groups>
  <group name="default">
    <users>
      <X-PRE-PROCESS cmd="include" data="default/*.xml"/>
      <X-PRE-PROCESS cmd="include" data="/tmp/siprecepta/*.xml"/>
    </users>
  </group>
</groups>
```

### Global variables

Put the following variables into _/etc/freeswitch/vars.xml_:

```xml
<X-PRE-PROCESS cmd="set" data="component_selector_url=https://domain/path"/>
<X-PRE-PROCESS cmd="set" data="component_selector_verify=false"/>
<X-PRE-PROCESS cmd="set" data="component_selector_token=eyJhbG..."/>
```

`component_selector_verify` should be `false` if `Jitsi-Component-Selector` has
not a trusted certificate.

`component_selector_token` is needed if `PROTECTED_SIGNAL_API` is enabled for
`Jitsi-Component-Selector`. Generate the token by running the following
commands:

```bash
PRIVATE_KEY_FILE="/path/to/signal.key"

HEADER=$(echo -n '{"alg":"RS256","typ":"JWT","kid":"jitsi/signal"}' | \
  base64 | tr '+/' '-_' | tr -d '=\n')
PAYLOAD=$(echo -n '{"iss":"signal","aud":"jitsi-component-selector"}' | \
  base64 | tr '+/' '-_' | tr -d '=\n')
SIGN=$(echo -n "$HEADER.$PAYLOAD" | \
  openssl dgst -sha256 -binary -sign $PRIVATE_KEY_FILE | \
  openssl enc -base64 | tr '+/' '-_' | tr -d '=\n')

TOKEN="$HEADER.$PAYLOAD.$SIGN"
echo $TOKEN
```

### Restart

Restart the service:

```bash
systemctl restart freeswitch
```

## Usage

Call the number set in
[98_public_siprecepta_dialplan.xml](files/98_public_siprecepta_dialplan.xml).
e.g.:

```
112233@freeswitch_address:5080
```

Type PIN when asked. For know there is a hardcoded value which is `123456`.
