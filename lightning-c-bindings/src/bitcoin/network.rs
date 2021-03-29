//! A C-mapped version fo bitcoin::network::constants::Network

use bitcoin::network::constants::Network as BitcoinNetwork;

#[repr(C)]
/// An enum representing the possible Bitcoin or test networks which we can run on
pub enum Network {
	/// The main Bitcoin blockchain.
	Bitcoin,
	/// The testnet3 blockchain.
	Testnet,
	/// A local test blockchain.
	Regtest,
	/// A blockchain on which blocks are signed instead of mined.
	Signet,
}

impl Network {
	pub(crate) fn into_bitcoin(&self) -> BitcoinNetwork {
		match self {
			Network::Bitcoin => BitcoinNetwork::Bitcoin,
			Network::Testnet => BitcoinNetwork::Testnet,
			Network::Regtest => BitcoinNetwork::Regtest,
			Network::Signet => BitcoinNetwork::Signet,
		}
	}
	pub(crate) fn from_bitcoin(net: BitcoinNetwork) -> Self {
		match net {
			BitcoinNetwork::Bitcoin => Network::Bitcoin,
			BitcoinNetwork::Testnet => Network::Testnet,
			BitcoinNetwork::Regtest => Network::Regtest,
			BitcoinNetwork::Signet => Network::Signet,
		}
	}
}
