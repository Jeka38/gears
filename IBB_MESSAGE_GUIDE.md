# In-Band Bytestreams (IBB) using Message Stanzas

This document provides a guide for using In-Band Bytestreams (IBB) with `<message/>` stanzas, as specified in [XEP-0047: In-Band Bytestreams](https://xmpp.org/extensions/xep-0047.html).

## Overview

IBB allows two entities to establish a virtual bytestream over XMPP by breaking data into Base64-encoded chunks and transporting them within XMPP stanzas. While `<iq/>` stanzas are the most common method for IBB, the protocol also supports using `<message/>` stanzas.

### Advantages of Message Stanzas

- **Delivery Assurance:** When using `<message/>` stanzas, Advanced Message Processing (XEP-0079) can be used to ensure that data packets are not spooled or sent to the wrong resource.
- **Better Throughput (sometimes):** In some server implementations, `<message/>` stanzas might be processed with lower latency or higher priority than `<iq/>` stanzas for large streams.

### Disadvantages

- **Overhead:** Message stanzas can have more overhead than IQ stanzas, depending on the server's handling and the inclusion of extra attributes.
- **Lack of Acknowledgments:** Unlike IQ stanzas, which require an immediate result or error response, message stanzas do not have a built-in application-level acknowledgment (unless using XEP-0184 or similar).

## Protocol Specification

### Negotiation via Jingle

To use message stanzas, the `stanzas` attribute must be set to `"message"` in the transport negotiation (Jingle).

**Example Jingle `session-initiate` with IBB Message Transport:**

```xml
<iq from='romeo@montague.net/orchard'
    id='jingle1'
    to='juliet@capulet.com/balcony'
    type='set'>
  <jingle xmlns='urn:xmpp:jingle:1'
          action='session-initiate'
          initiator='romeo@montague.net/orchard'
          sid='a73sjj76as92'>
    <content creator='initiator' name='ex'>
      <description xmlns='urn:xmpp:jingle:apps:file-transfer:5'>
        <file>
          <name>test.txt</name>
          <size>1024</size>
        </file>
      </description>
      <transport xmlns='urn:xmpp:jingle:transports:ibb:1'
                 block-size='4096'
                 sid='mySID'
                 stanzas='message'/>
    </content>
  </jingle>
</iq>
```

### Sending Data

When `stanzas="message"` is negotiated, data chunks are sent within `<message/>` stanzas.

**Example Data Stanza:**

```xml
<message from='romeo@montague.net/orchard'
         id='msg1'
         to='juliet@capulet.com/balcony'>
  <data xmlns='http://jabber.org/protocol/ibb'
        seq='0'
        sid='mySID'>
    BASE64_DATA_HERE
  </data>
</message>
```

## Bot Implementation Notes

The bot supports and preserves the `stanzas` attribute during Jingle negotiations. It will correctly accept an IBB transport with `stanzas="message"` and log the signaling stanzas while truncating the actual data chunks to maintain log readability.

- **Negotiation:** The bot checks for the `stanzas` attribute in `session-initiate`, `transport-replace`, and `transport-accept` actions and reflects the negotiated value in its responses.
- **Logging:** All IBB signaling is logged. Data chunks, whether in `<iq/>` or `<message/>` stanzas, have their Base64 text truncated in the logs.
