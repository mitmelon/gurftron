#[feature("deprecated-starknet-consts")]

// g_utils - Utility library for Starknet/Cairo
// Author: Adeyeye George
// Version: 1.1.0
// Contact: manomitehq@gmail.com
// License: MIT

use starknet::{ContractAddress, contract_address_const};

// Trait for resetting values to their "null" state
trait GResettable<T> {
    fn g_reset(ref self: T) -> T;
}

// Implementations for resetting standard Cairo types
impl Felt252GResettable of GResettable<felt252> {
    fn g_reset(ref self: felt252) -> felt252 { 0 }
}

impl U8GResettable of GResettable<u8> {
    fn g_reset(ref self: u8) -> u8 { 0 }
}

impl U16GResettable of GResettable<u16> {
    fn g_reset(ref self: u16) -> u16 { 0 }
}

impl U32GResettable of GResettable<u32> {
    fn g_reset(ref self: u32) -> u32 { 0 }
}

impl U64GResettable of GResettable<u64> {
    fn g_reset(ref self: u64) -> u64 { 0 }
}

impl U128GResettable of GResettable<u128> {
    fn g_reset(ref self: u128) -> u128 { 0 }
}

impl U256GResettable of GResettable<u256> {
    fn g_reset(ref self: u256) -> u256 { 0 }
}

impl BoolGResettable of GResettable<bool> {
    fn g_reset(ref self: bool) -> bool { false }
}

impl ByteArrayGResettable of GResettable<ByteArray> {
    fn g_reset(ref self: ByteArray) -> ByteArray { "" }
}

impl ContractAddressGResettable of GResettable<ContractAddress> {
    fn g_reset(ref self: ContractAddress) -> ContractAddress {
        contract_address_const::<0>()
    }
}

impl OptionGResettable<T, impl TGResettable: GResettable<T>, impl TDrop: Drop<T>> of GResettable<Option<T>> {
    fn g_reset(ref self: Option<T>) -> Option<T> { Option::None }
}

impl ArrayGResettable<T, impl TDrop: Drop<T>> of GResettable<Array<T>> {
    fn g_reset(ref self: Array<T>) -> Array<T> { array![] }
}

// Note: Vec and Map reset are omitted due to storage constraints

// Dynamic typing system for flexible type conversions
#[derive(Drop, Serde)]
enum g_convert {
    Felt252: felt252,
    U8: u8,
    U16: u16,
    U32: u32,
    U64: u64,
    U128: u128,
    U256: u256,
    Bool: bool,
    ByteArray: ByteArray,
    ContractAddress: ContractAddress,
}

// Trait for type conversion
trait g_convertTrait {
    fn new<T, impl TDrop: Drop<T>, impl TIntoDynamic: Into<T, g_convert>>(value: T) -> g_convert;
    fn g_convert<T, impl TDrop: Drop<T>, impl TFromDynamic: TryInto<g_convert, T>>(self: g_convert) -> T;
    fn to(self: g_convert, other: g_convert) -> felt252;
    fn to_string(self: g_convert) -> ByteArray;
}

impl g_convertImpl of g_convertTrait {
    fn new<T, impl TDrop: Drop<T>, impl TIntoDynamic: Into<T, g_convert>>(value: T) -> g_convert {
        value.into()
    }

    fn g_convert<T, impl TDrop: Drop<T>, impl TFromDynamic: TryInto<g_convert, T>>(self: g_convert) -> T {
        match self.try_into() {
            Option::Some(value) => value,
            Option::None => panic_with_felt252('conversion_failed'),
        }
    }

    fn to(self: g_convert, other: g_convert) -> felt252 {
        match self {
            g_convert::Felt252(v) => v,
            g_convert::U8(v) => v.into(),
            g_convert::U16(v) => v.into(),
            g_convert::U32(v) => v.into(),
            g_convert::U64(v) => v.into(),
            g_convert::U128(v) => v.into(),
            g_convert::U256(v) => match v.try_into() {
                Option::Some(felt_val) => felt_val,
                Option::None => 0,
            },
            g_convert::Bool(v) => if v { 1 } else { 0 },
            _ => 0,
        }
    }

    fn to_string(self: g_convert) -> ByteArray {
        match self {
            g_convert::ByteArray(v) => v,
            g_convert::Felt252(v) => format!("{}", v),
            g_convert::U8(v) => format!("{}", v),
            g_convert::U16(v) => format!("{}", v),
            g_convert::U32(v) => format!("{}", v),
            g_convert::U64(v) => format!("{}", v),
            g_convert::U128(v) => format!("{}", v),
            g_convert::U256(v) => format!("{}", v),
            g_convert::Bool(v) => if v { "true" } else { "false" },
            g_convert::ContractAddress(v) => format!("{:?}", v),
        }
    }
}

// === Into implementations ===
impl Felt252IntoDynamic of Into<felt252, g_convert> { fn into(self: felt252) -> g_convert { g_convert::Felt252(self) } }
impl U8IntoDynamic of Into<u8, g_convert> { fn into(self: u8) -> g_convert { g_convert::U8(self) } }
impl U16IntoDynamic of Into<u16, g_convert> { fn into(self: u16) -> g_convert { g_convert::U16(self) } }
impl U32IntoDynamic of Into<u32, g_convert> { fn into(self: u32) -> g_convert { g_convert::U32(self) } }
impl U64IntoDynamic of Into<u64, g_convert> { fn into(self: u64) -> g_convert { g_convert::U64(self) } }
impl U128IntoDynamic of Into<u128, g_convert> { fn into(self: u128) -> g_convert { g_convert::U128(self) } }
impl U256IntoDynamic of Into<u256, g_convert> { fn into(self: u256) -> g_convert { g_convert::U256(self) } }
impl BoolIntoDynamic of Into<bool, g_convert> { fn into(self: bool) -> g_convert { g_convert::Bool(self) } }
impl ByteArrayIntoDynamic of Into<ByteArray, g_convert> { fn into(self: ByteArray) -> g_convert { g_convert::ByteArray(self) } }
impl ContractAddressIntoDynamic of Into<ContractAddress, g_convert> { fn into(self: ContractAddress) -> g_convert { g_convert::ContractAddress(self) } }

// === TryInto implementations ===
impl Felt252FromDynamic of TryInto<g_convert, felt252> {
    fn try_into(self: g_convert) -> Option<felt252> {
        match self {
            g_convert::Felt252(v) => Option::Some(v),
            g_convert::U8(v) => Option::Some(v.into()),
            g_convert::U16(v) => Option::Some(v.into()),
            g_convert::U32(v) => Option::Some(v.into()),
            g_convert::U64(v) => Option::Some(v.into()),
            g_convert::U128(v) => Option::Some(v.into()),
            g_convert::Bool(v) => Option::Some(if v { 1 } else { 0 }),
            _ => Option::None,
        }
    }
}

impl U8FromDynamic of TryInto<g_convert, u8> {
    fn try_into(self: g_convert) -> Option<u8> {
        match self {
            g_convert::U8(v) => Option::Some(v),
            g_convert::Felt252(v) => v.try_into(),
            _ => Option::None,
        }
    }
}

impl U16FromDynamic of TryInto<g_convert, u16> {
    fn try_into(self: g_convert) -> Option<u16> {
        match self {
            g_convert::U16(v) => Option::Some(v),
            g_convert::Felt252(v) => v.try_into(),
            g_convert::U8(v) => Option::Some(v.into()),
            _ => Option::None,
        }
    }
}

impl U32FromDynamic of TryInto<g_convert, u32> {
    fn try_into(self: g_convert) -> Option<u32> {
        match self {
            g_convert::U32(v) => Option::Some(v),
            g_convert::Felt252(v) => v.try_into(),
            g_convert::U8(v) => Option::Some(v.into()),
            g_convert::U16(v) => Option::Some(v.into()),
            _ => Option::None,
        }
    }
}

impl U64FromDynamic of TryInto<g_convert, u64> {
    fn try_into(self: g_convert) -> Option<u64> {
        match self {
            g_convert::U64(v) => Option::Some(v),
            g_convert::Felt252(v) => v.try_into(),
            g_convert::U8(v) => Option::Some(v.into()),
            g_convert::U16(v) => Option::Some(v.into()),
            g_convert::U32(v) => Option::Some(v.into()),
            _ => Option::None,
        }
    }
}

impl U128FromDynamic of TryInto<g_convert, u128> {
    fn try_into(self: g_convert) -> Option<u128> {
        match self {
            g_convert::U128(v) => Option::Some(v),
            g_convert::Felt252(v) => v.try_into(),
            g_convert::U8(v) => Option::Some(v.into()),
            g_convert::U16(v) => Option::Some(v.into()),
            g_convert::U32(v) => Option::Some(v.into()),
            g_convert::U64(v) => Option::Some(v.into()),
            _ => Option::None,
        }
    }
}

impl U256FromDynamic of TryInto<g_convert, u256> {
    fn try_into(self: g_convert) -> Option<u256> {
        match self {
            g_convert::U256(v) => Option::Some(v),
            g_convert::Felt252(v) => Option::Some(v.into()),
            g_convert::U8(v) => Option::Some(v.into()),
            g_convert::U16(v) => Option::Some(v.into()),
            g_convert::U32(v) => Option::Some(v.into()),
            g_convert::U64(v) => Option::Some(v.into()),
            g_convert::U128(v) => Option::Some(v.into()),
            _ => Option::None,
        }
    }
}

impl BoolFromDynamic of TryInto<g_convert, bool> {
    fn try_into(self: g_convert) -> Option<bool> {
        match self {
            g_convert::Bool(v) => Option::Some(v),
            g_convert::Felt252(v) => Option::Some(v != 0),
            g_convert::U8(v) => Option::Some(v != 0),
            g_convert::U16(v) => Option::Some(v != 0),
            g_convert::U32(v) => Option::Some(v != 0),
            g_convert::U64(v) => Option::Some(v != 0),
            g_convert::U128(v) => Option::Some(v != 0),
            g_convert::U256(v) => Option::Some(v != 0),
            _ => Option::None,
        }
    }
}

impl ByteArrayFromDynamic of TryInto<g_convert, ByteArray> {
    fn try_into(self: g_convert) -> Option<ByteArray> {
        match self {
            g_convert::ByteArray(v) => Option::Some(v),
            g_convert::Felt252(v) => Option::Some(format!("{}", v)),
            g_convert::U8(v) => Option::Some(format!("{}", v)),
            g_convert::U16(v) => Option::Some(format!("{}", v)),
            g_convert::U32(v) => Option::Some(format!("{}", v)),
            g_convert::U64(v) => Option::Some(format!("{}", v)),
            g_convert::U128(v) => Option::Some(format!("{}", v)),
            g_convert::U256(v) => Option::Some(format!("{}", v)),
            g_convert::Bool(v) => Option::Some(if v { "true" } else { "false" }),
            _ => Option::None,
        }
    }
}

impl ContractAddressFromDynamic of TryInto<g_convert, ContractAddress> {
    fn try_into(self: g_convert) -> Option<ContractAddress> {
        match self {
            g_convert::ContractAddress(v) => Option::Some(v),
            _ => Option::None,
        }
    }
}