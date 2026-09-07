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
}
