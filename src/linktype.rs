//! [`LinkType`]: which link-layer header a packet is assumed to start with.

/// The link-layer framing a compiled program expects packets to start with.
///
/// `non_exhaustive`: new link types get added to this enum over time (there are dozens in the
/// wild), and that must not be a breaking change for existing `match`es.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Standard 14-byte Ethernet II framing.
    Ethernet,
    /// Linux "cooked" capture framing (`LINKTYPE_LINUX_SLL`), what you get capturing on the `any` pseudo-interface.
    LinuxSll,
    /// No link-layer framing at all - the packet starts directly at the network-layer (e.g. IP) header.
    Raw,
}

/// The link-layer offset info that codegen needs: where the network-layer header starts, and - if this link type
/// multiplexes several network-layer protocols over one wire format - where the fieldthat says which one is.
pub(crate) struct L3OffsetInfo {
    pub ip_base: u32, // offset of IP start
    pub ethertype_offset: Option<u32>,
}

impl LinkType {
    /// Convert from a `LINKTYPE_*` value, the number stored in a pcap savefile's global header
    /// (see the registry at <https://www.tcpdump.org/linktypes.html>).
    pub fn from_dlt(v: u16) -> Option<Self> {
        match v {
            1 => Some(LinkType::Ethernet),
            101 => Some(LinkType::Raw),
            113 => Some(LinkType::LinuxSll),
            _ => None,
        }
    }

    /// The inverse of [`LinkType::from_dlt`].
    pub fn to_dlt(self) -> u16 {
        match self {
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::LinuxSll => 113,
        }
    }

    /// For each link type return IP base offset and ethtype offset of the header.
    pub(crate) fn l3_offset_info(self) -> L3OffsetInfo {
        match self {
            // 14-byte IP base, Ethernet header: 6 dst + 6 src + 2 ethertype
            LinkType::Ethernet => L3OffsetInfo {
                ip_base: 14,
                ethertype_offset: Some(12),
            },

            // 16-byte IP base, LinuxSll header: 2 packet-type + 2 ARPHRD_* + 2 addr-len + 8 padded address + 2 protocol-type
            LinkType::LinuxSll => L3OffsetInfo {
                ip_base: 16,
                ethertype_offset: Some(14),
            },

            // 0-bute IP base, so Raw packet: no framing at all, we start from IP
            LinkType::Raw => L3OffsetInfo {
                ip_base: 0,
                ethertype_offset: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlt_roundtrips() {
        for lt in [LinkType::Ethernet, LinkType::LinuxSll, LinkType::Raw] {
            assert_eq!(LinkType::from_dlt(lt.to_dlt()), Some(lt));
        }
    }

    #[test]
    fn unknown_dlt_is_none() {
        assert_eq!(LinkType::from_dlt(0xffff), None);
    }

    #[test]
    fn ethernet_has_an_ethertype_field() {
        assert!(
            LinkType::Ethernet
                .l3_offset_info()
                .ethertype_offset
                .is_some()
        );
    }
}
