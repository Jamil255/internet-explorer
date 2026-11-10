// Plain-language explanations for header fields, shown in the packet inspector.
// Keys are field names as written by the encoders; layer-specific keys use "layer:field".

const HELP: Record<string, string> = {
  // Ethernet
  'eth:Destination MAC': 'The next device on this link that should take the frame — usually the router for anything off the local network.',
  'eth:Source MAC': 'The hardware address of the network card that sent this frame.',
  'eth:EtherType': 'Which protocol is inside the frame, so the receiver knows how to read the rest.',
  // IPv4
  'ip:Version · Header length': 'IP version 4, and a 20-byte header (no options).',
  'ip:Differentiated services': 'Priority and congestion marks. Zero means ordinary best-effort traffic.',
  'ip:Total length': 'Size of this IP header plus everything inside it.',
  'ip:Identification': 'Lets the receiver put fragments back together if the packet is ever split.',
  'ip:Flags · Fragment offset': "“Don't fragment” asks routers not to split this packet; the offset says where a fragment belongs.",
  'ip:Time to live': 'Each router subtracts one; at zero the packet is dropped. Stops packets looping forever.',
  'ip:Protocol': 'Which transport protocol the payload uses (6 = TCP, 17 = UDP, 1 = ICMP).',
  'ip:Header checksum': 'Protects only the IP header. Every router recomputes it after lowering the TTL.',
  'ip:Source address': 'Who sent the packet.',
  'ip:Destination address': 'Where the packet is going. Routers forward hop by hop based on this.',
  // IPv6
  'ip:Version · Traffic class · Flow label': 'IP version 6, a priority class and a label routers can use to keep a flow together.',
  'ip:Payload length': 'Size of everything after the fixed 40-byte IPv6 header.',
  'ip:Next header': 'What comes after the IPv6 header (6 = TCP, 17 = UDP, 58 = ICMPv6).',
  'ip:Hop limit': 'IPv6’s TTL: decremented by every router, dropped at zero.',
  // TCP
  'tcp:Source port': 'The sending application’s port. Clients pick a random high “ephemeral” port.',
  'tcp:Destination port': 'The service being contacted, e.g. 80 for HTTP or 443 for HTTPS.',
  'tcp:Sequence number': 'Position of this segment’s first byte in the stream. Shown relative to the random starting number.',
  'tcp:Acknowledgment number': 'The next byte expected from the other side — everything before it has arrived.',
  'tcp:Header length · Flags': 'Header size, then control flags: SYN opens, ACK acknowledges, PSH delivers now, FIN closes, RST aborts.',
  'tcp:Window size': 'How many more bytes the sender of this segment is ready to receive (flow control).',
  'tcp:Checksum': 'Covers the TCP header, data and parts of the IP header; a mismatch means the segment is discarded.',
  'tcp:Urgent pointer': 'Almost never used; zero here.',
  'tcp:Option: Maximum segment size': 'The largest chunk of data this side wants in one segment (1460 fits a 1500-byte Ethernet frame).',
  // UDP
  'udp:Source port': 'The sending application’s port. Replies come back to it.',
  'udp:Destination port': 'The service being contacted, e.g. 53 for DNS or 123 for NTP.',
  'udp:Length': 'Size of the 8-byte UDP header plus the data.',
  'udp:Checksum': 'Detects corruption of the header and data.',
  // ICMP
  'icmp:Type': 'What kind of ICMP message this is.',
  'icmp:Code': 'More detail about the type.',
  'icmp:Checksum': 'Detects corruption of the ICMP message.',
  'icmp:Identifier': 'Matches replies to the ping process that sent the request.',
  'icmp:Sequence number': 'Counts the pings, so lost or reordered replies can be spotted.',
  'icmp:Data': 'Filler bytes the target copies back unchanged.',
  // DNS
  'app:Transaction ID': 'A random number the reply must echo, so the asker can match answers to questions.',
  'app:Query': 'The name being looked up and the record type wanted.',
  'app:Answer': 'A record answering the question, with how long it may be cached (TTL).',
  'app:Authority': 'A referral: the nameservers to ask next.',
  'app:Additional': '“Glue” addresses for the referred nameservers, saving another lookup.',
  // TLS
  'app:Random': 'Fresh random bytes mixed into the keys, so every session is unique.',
  'app:Encrypted data': 'Ciphertext. Without the session keys it looks like random noise.',
  'app:Extension · server_name (SNI)': 'The site name, sent unencrypted so the server knows which certificate to use.',
  'app:Extension · key_share': 'This side’s public key for the Diffie-Hellman exchange.',
  'app:Cipher suites': 'The encryption algorithms this side supports, in order of preference.',
};

/** Fields whose value is only an example: it changes in every real capture. */
const EXAMPLE = new Set([
  'Identification',
  'Header checksum',
  'Checksum',
  'Transaction ID',
  'Random',
  'Session ID',
  'Session ID (echoed)',
  'Masking key',
  'Encrypted data',
  'Source MAC',
  'Destination MAC',
  'Client MAC (chaddr)',
  'Extension · key_share',
  'Sequence number',
  'Acknowledgment number',
]);

export function fieldHelp(layerKey: string, name: string): string | undefined {
  return HELP[`${layerKey}:${name}`] ?? HELP[`app:${name}`];
}

export function isExample(layerKey: string, name: string, value: string): boolean {
  if (EXAMPLE.has(name)) return !(layerKey === 'icmp' && name === 'Sequence number');
  if (layerKey === 'tcp' || layerKey === 'udp') {
    if (name === 'Source port' || name === 'Destination port') return Number(value) >= 49152;
  }
  return /random|encrypted/i.test(value);
}
