use crate::{Compact, CompactPlaceholder};
use alloc::vec::Vec;
use alloy_consensus::TxEip4844 as AlloyTxEip4844;
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, ChainId, B256, U256};
use reth_codecs_derive::add_arbitrary_tests;

/// [EIP-4844 Blob Transaction](https://eips.ethereum.org/EIPS/eip-4844#blob-transaction)
///
/// This is a helper type to use derive on it instead of manually managing `bitfield`.
///
/// By deriving `Compact` here, any future changes or enhancements to the `Compact` derive
/// will automatically apply to this type.
///
/// Notice: Make sure this struct is 1:1 with [`alloy_consensus::TxEip4844`]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Compact)]
#[cfg_attr(test, derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize))]
#[add_arbitrary_tests(compact)]
pub(crate) struct TxEip4844 {
    chain_id: ChainId,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    /// TODO(debt): this should be removed if we break the DB.
    /// Makes sure that the Compact bitflag struct has one bit after the above field:
    /// <https://github.com/paradigmxyz/reth/pull/8291#issuecomment-2117545016>
    placeholder: Option<CompactPlaceholder>,
    to: Address,
    value: U256,
    access_list: AccessList,
    blob_versioned_hashes: Vec<B256>,
    max_fee_per_blob_gas: u128,
    input: Bytes,
}

impl Compact for AlloyTxEip4844 {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let tx = TxEip4844 {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            placeholder: Some(()),
            to: self.to,
            value: self.value,
            access_list: self.access_list.clone(),
            blob_versioned_hashes: self.blob_versioned_hashes.clone(),
            max_fee_per_blob_gas: self.max_fee_per_blob_gas,
            input: self.input.clone(),
        };
        tx.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (tx, _) = TxEip4844::from_compact(buf, len);
        let alloy_tx = Self {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            to: tx.to,
            value: tx.value,
            access_list: tx.access_list,
            blob_versioned_hashes: tx.blob_versioned_hashes,
            max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
            input: tx.input,
        };
        (alloy_tx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};

    #[test]
    fn backwards_compatible_txkind_test() {
        // TxEip4844 encoded with TxKind on to field
        // holesky tx hash: <0xa3b1668225bf0fbfdd6c19aa6fd071fa4ff5d09a607c67ccd458b97735f745ac>
        let tx = bytes!("224348a100426844cb2dc6c0b2d05e003b9aca0079c9109b764609df928d16fc4a91e9081f7e87db09310001019101fb28118ceccaabca22a47e35b9c3f12eb2dcb25e5c543d5b75e6cd841f0a05328d26ef16e8450000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000004c000000000000000000000000000000000000000000000000000000000000000200000000000000000000000007b399987d24fc5951f3e94a4cb16e87414bf22290000000000000000000000001670090000000000000000000000000000010001302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000009e640a6aadf4f664cf467b795c31332f44acbe6c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006614c2d1000000000000000000000000000000000000000000000000000000000014012c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000093100000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000093100000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041f06fd78f4dcdf089263524731620941747b9b93fd8f631557e25b23845a78b685bd82f9d36bce2f4cc812b6e5191df52479d349089461ffe76e9f2fa2848a0fe1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410819f04aba17677807c61ae72afdddf7737f26931ecfa8af05b7c669808b36a2587e32c90bb0ed2100266dd7797c80121a109a2b0fe941ca5a580e438988cac81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let (tx, _) = TxEip4844::from_compact(&tx, tx.len());
        assert_eq!(tx.to, address!("79C9109b764609df928d16fC4a91e9081F7e87DB"));
        assert_eq!(tx.placeholder, Some(()));
        assert_eq!(tx.input, bytes!("ef16e8450000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000004c000000000000000000000000000000000000000000000000000000000000000200000000000000000000000007b399987d24fc5951f3e94a4cb16e87414bf22290000000000000000000000001670090000000000000000000000000000010001302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000009e640a6aadf4f664cf467b795c31332f44acbe6c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006614c2d1000000000000000000000000000000000000000000000000000000000014012c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000093100000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000093100000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041f06fd78f4dcdf089263524731620941747b9b93fd8f631557e25b23845a78b685bd82f9d36bce2f4cc812b6e5191df52479d349089461ffe76e9f2fa2848a0fe1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410819f04aba17677807c61ae72afdddf7737f26931ecfa8af05b7c669808b36a2587e32c90bb0ed2100266dd7797c80121a109a2b0fe941ca5a580e438988cac81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
    }
}
