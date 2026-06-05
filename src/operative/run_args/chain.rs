/// Chain type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Chain {
    // For local tests (./tests/) involving db operations.
    Testbed,
    // For signet.
    Signet,
    // For mainnet.
    Mainnet,
    // For a local regtest network.
    Regtest,
}

impl ToString for Chain {
    fn to_string(&self) -> String {
        match self {
            Chain::Testbed => "testbed".to_string(),
            Chain::Signet => "signet".to_string(),
            Chain::Mainnet => "mainnet".to_string(),
            Chain::Regtest => "regtest".to_string(),
        }
    }
}