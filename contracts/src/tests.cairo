// Test suite for g_utils library
// This should be in a separate tests.cairo file or at the bottom of your main lib.cairo

#[cfg(test)]
mod tests {
    use starknet::{ContractAddress, contract_address_const};
    use super::{
        GResettable, g_convert, g_convertTrait, g_assert,
        Felt252GResettable, U8GResettable, U16GResettable, U32GResettable,
        U64GResettable, U128GResettable, U256GResettable, BoolGResettable,
        ByteArrayGResettable, ContractAddressGResettable, OptionGResettable,
        VecGResettable, ArrayGResettable
    };

    #[test]
    fn test_felt252_reset() {
        let mut value: felt252 = 42;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'Felt252 should reset to 0');
    }

    #[test]
    fn test_u8_reset() {
        let mut value: u8 = 255;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U8 should reset to 0');
    }

    #[test]
    fn test_u16_reset() {
        let mut value: u16 = 65535;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U16 should reset to 0');
    }

    #[test]
    fn test_u32_reset() {
        let mut value: u32 = 4294967295;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U32 should reset to 0');
    }

    #[test]
    fn test_u64_reset() {
        let mut value: u64 = 18446744073709551615;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U64 should reset to 0');
    }

    #[test]
    fn test_u128_reset() {
        let mut value: u128 = 340282366920938463463374607431768211455;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U128 should reset to 0');
    }

    #[test]
    fn test_u256_reset() {
        let mut value: u256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
        let reset_value = value.g_reset();
        assert(reset_value == 0, 'U256 should reset to 0');
    }

    #[test]
    fn test_bool_reset() {
        let mut value: bool = true;
        let reset_value = value.g_reset();
        assert(reset_value == false, 'Bool should reset to false');
    }

    #[test]
    fn test_bytearray_reset() {
        let mut value: ByteArray = "Hello, World!";
        let reset_value = value.g_reset();
        assert(reset_value == "", 'ByteArray should reset to empty');
    }

    #[test]
    fn test_contract_address_reset() {
        let mut value: ContractAddress = contract_address_const::<0x123>();
        let reset_value = value.g_reset();
        let zero_addr = contract_address_const::<0>();
        assert(reset_value == zero_addr, 'Address should reset to zero');
    }

    #[test]
    fn test_option_reset() {
        let mut value: Option<felt252> = Option::Some(42);
        let reset_value = value.g_reset();
        match reset_value {
            Option::Some(_) => panic!("Option should reset to None"),
            Option::None => {},
        }
    }

    #[test]
    fn test_array_reset() {
        let mut arr = array![1, 2, 3];
        let reset_arr = arr.g_reset();
        assert(reset_arr.len() == 0, 'Array should reset to empty');
    }

    #[test]
    fn test_g_assert_true() {
        g_assert(true, "This should not panic");
    }

    #[test]
    #[should_panic]
    fn test_g_assert_false() {
        g_assert(false, "This should panic");
    }

    #[test]
    fn test_g_convert_creation() {
        let _felt_val = g_convertTrait::new(42_felt252);
        let _u8_val = g_convertTrait::new(255_u8);
        let _bool_val = g_convertTrait::new(true);
        let _str_val: g_convert = g_convertTrait::new("Hello");
    }

    #[test]
    fn test_felt252_conversion() {
        let dynamic_val = g_convertTrait::new(42_felt252);
        let converted: felt252 = dynamic_val.g_convert();
        assert(converted == 42, 'Felt252 conversion failed');
    }

    #[test]
    fn test_u8_conversion() {
        let dynamic_val = g_convertTrait::new(255_u8);
        let converted: u8 = dynamic_val.g_convert();
        assert(converted == 255, 'U8 conversion failed');
    }

    #[test]
    fn test_bool_conversion() {
        let dynamic_val = g_convertTrait::new(true);
        let converted: bool = dynamic_val.g_convert();
        assert(converted == true, 'Bool conversion failed');
    }

    #[test]
    fn test_cross_type_conversion() {
        let u8_val = g_convertTrait::new(42_u8);
        let as_felt: felt252 = u8_val.g_convert();
        assert(as_felt == 42, 'U8 to felt252 conversion failed');
    }

    #[test]
    fn test_to_string_conversions() {
        let felt_val = g_convertTrait::new(42_felt252);
        let str_result = felt_val.to_string();
        assert(str_result == "42", 'Felt252 to string failed');

        let bool_val = g_convertTrait::new(true);
        let bool_str = bool_val.to_string();
        assert(bool_str == "true", 'Bool to string failed');

        let false_val = g_convertTrait::new(false);
        let false_str = false_val.to_string();
        assert(false_str == "false", 'Bool false to string failed');
    }

    #[test]
    fn test_numeric_to_conversions() {
        let val1 = g_convertTrait::new(42_felt252);
        let val2 = g_convertTrait::new(10_u8);
        
        // Clone values to avoid move errors
        let val1_clone = g_convertTrait::new(42_felt252);
        let val2_clone = g_convertTrait::new(10_u8);
        
        let result1 = val1.to(val2);
        assert(result1 == 42, 'Numeric conversion 1 failed');

        let result2 = val2_clone.to(val1_clone);
        assert(result2 == 10, 'Numeric conversion 2 failed');
    }

    #[test]
    fn test_bool_numeric_conversions() {
        let true_val = g_convertTrait::new(true);
        let false_val = g_convertTrait::new(false);
        
        // Clone values to avoid move errors
        let true_val_clone = g_convertTrait::new(true);
        let false_val_clone = g_convertTrait::new(false);
        
        let true_result = true_val.to(false_val);
        assert(true_result == 1, 'True should convert to 1');
        
        let false_result = false_val_clone.to(true_val_clone);
        assert(false_result == 0, 'False should convert to 0');
    }

    #[test]
    fn test_u256_conversions() {
        let large_val = g_convertTrait::new(1000_u256);
        let large_val_clone = g_convertTrait::new(1000_u256);
        
        let str_result = large_val.to_string();
        assert(str_result == "1000", 'U256 to string failed');
        
        let small_val = g_convertTrait::new(42_felt252);
        let result = large_val_clone.to(small_val);
        assert(result == 1000, 'U256 conversion failed');
    }

    #[test]
    fn test_contract_address_conversion() {
        let addr = contract_address_const::<0x123>();
        let dynamic_addr = g_convertTrait::new(addr);
        let converted: ContractAddress = dynamic_addr.g_convert();
        assert(converted == addr, 'Address conversion failed');
    }

    #[test]
    fn test_type_conversions_between_numeric_types() {
        // Test u8 to u16
        let u8_val = g_convertTrait::new(100_u8);
        let as_u16: u16 = u8_val.g_convert();
        assert(as_u16 == 100_u16, 'U8 to U16 failed');

        // Test u16 to u32
        let u16_val = g_convertTrait::new(1000_u16);
        let as_u32: u32 = u16_val.g_convert();
        assert(as_u32 == 1000_u32, 'U16 to U32 failed');

        // Test felt252 to various types
        let felt_val = g_convertTrait::new(50_felt252);
        let as_u8: u8 = felt_val.g_convert();
        assert(as_u8 == 50_u8, 'Felt252 to U8 failed');
    }

    #[test]
    fn test_numeric_to_bool_conversions() {
        let zero_felt = g_convertTrait::new(0_felt252);
        let nonzero_felt = g_convertTrait::new(42_felt252);
        
        let zero_bool: bool = zero_felt.g_convert();
        let nonzero_bool: bool = nonzero_felt.g_convert();
        
        assert(zero_bool == false, 'Zero should convert to false');
        assert(nonzero_bool == true, 'Nonzero should convert to true');
    }

    #[test]
    fn test_all_numeric_string_conversions() {
        let u8_val = g_convertTrait::new(255_u8);
        assert(u8_val.to_string() == "255", 'U8 string conversion failed');
        
        let u16_val = g_convertTrait::new(65535_u16);
        assert(u16_val.to_string() == "65535", 'U16 string conversion failed');
        
        let u32_val = g_convertTrait::new(4294967295_u32);
        assert(u32_val.to_string() == "4294967295", 'U32 string conversion failed');
        
        let u64_val = g_convertTrait::new(18446744073709551615_u64);
        assert(u64_val.to_string() == "18446744073709551615", 'U64 string failed');
    }

    // Integration test combining multiple features
    #[test]
    fn test_integration_reset_and_convert() {
        // Test resetting and then converting
        let mut original_value = 100_felt252;
        let reset_value = original_value.g_reset();
        
        let dynamic_reset = g_convertTrait::new(reset_value);
        let dynamic_reset_clone = g_convertTrait::new(reset_value);
        
        let as_bool: bool = dynamic_reset.g_convert();
        assert(as_bool == false, 'Reset value should be false as bool');
        
        let as_string = dynamic_reset_clone.to_string();
        assert(as_string == "0", 'Reset value should be "0" as string');
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values
        let zero_u256 = g_convertTrait::new(0_u256);
        let zero_u256_clone = g_convertTrait::new(0_u256);
        let zero_result = zero_u256.to(zero_u256_clone);
        assert(zero_result == 0, 'Zero conversion failed');
        
        // Test with maximum values
        let max_u8 = g_convertTrait::new(255_u8);
        let max_str = max_u8.to_string();
        assert(max_str == "255", 'Max u8 string failed');
    }

    // Test to verify all basic types can be wrapped and unwrapped
    #[test]
    fn test_roundtrip_conversions() {
        // felt252 roundtrip
        let original_felt = 12345_felt252;
        let wrapped = g_convertTrait::new(original_felt);
        let unwrapped: felt252 = wrapped.g_convert();
        assert(unwrapped == original_felt, 'Felt252 roundtrip failed');
        
        // u128 roundtrip
        let original_u128 = 123456789_u128;
        let wrapped = g_convertTrait::new(original_u128);
        let unwrapped: u128 = wrapped.g_convert();
        assert(unwrapped == original_u128, 'U128 roundtrip failed');
        
        // ByteArray roundtrip
        let original_str: ByteArray = "Test String";
        let wrapped = g_convertTrait::new(original_str.clone());
        let unwrapped: ByteArray = wrapped.g_convert();
        assert(unwrapped == original_str, 'ByteArray roundtrip failed');
    }
}