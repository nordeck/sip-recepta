# API

This is about getting the session data from Booking Portal by using PIN.

## PIN

- It must contain only numbers. Easy for SIP user.
- It must have a static length because of SIP server logic. 6 digits..?
- It must be unique from the consumer perspective, refers only to one meeting.
- It should be hard to guess.

## Request

- Input is `PIN`
- Output is a JSON object

  ```json
  host: "https://jitsi-domain",
  room: "room-name",
  token: "token-value-for-jitsi",
  displayname: "display-name-for-sip"
  ```

## Questions

- Do we need authentication for this service such as shared secret?
- Different PINs for moderator and guest?
- Always response when the moderator asks for the meeting data..?
- Response guest if all condition are OK (such as matching scheduled time...)
- What happens when the guest tries to join a room which is not openned yet?
  Guest should be allowed to join if it's time for the meeting.
