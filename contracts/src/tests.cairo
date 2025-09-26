#[cfg(test)]
mod tests {
    use starknet::{ContractAddress, contract_address_const};
    use crate::{
        GResettable,
        g_convert,
        g_convertTrait,
        Felt252GResettable,
        U8GResettable,
        U16GResettable,
        U32GResettable,
        U64GResettable,
        U128GResettable,
        U256GResettable,
        BoolGResettable,
        ByteArrayGResettable,
        ContractAddressGResettable,
        OptionGResettable,
        ArrayGResettable,
    };

    #[test]
    fn test_felt252_reset() {
        let value = 42_felt252;
        let reset_value = Felt252GResettable::g_reset(value);
        assert(reset_value == 0, 'Felt252 should reset to 0');
    }

    #[test]
    fn test_u8_reset() {
        let value = 255_u8;
        let reset_value = U8GResettable::g_reset(value);
        assert(reset_value == 0_u8, 'U8 should reset to 0');
    }

    #[test]
    fn test_bool_reset() {
        let value = true;
        let reset_value = BoolGResettable::g_reset(value);
        assert(reset_value == false, 'Bool should reset to false');
    }

    #[test]
    fn test_bytearray_reset() {
        let value: ByteArray = "Hello";
        let reset_value = ByteArrayGResettable::g_reset(value);
        assert(reset_value == "", 'ByteArray should reset to empty');
    }

    #[test]
    fn test_contract_address_reset() {
        let value = contract_address_const::<0x123>();
        let reset_value = ContractAddressGResettable::g_reset(value);
        let zero_addr = contract_address_const::<0>();
        assert(reset_value == zero_addr, 'Address should reset to zero');
    }

    #[test]
    fn test_option_reset() {
        let value: Option<felt252> = Option::Some(42_felt252);
        let reset_value = OptionGResettable::g_reset(value);
        match reset_value {
            Option::Some(_) => panic!("Should be None"),
            Option::None => {},
        }
    }

    #[test]
    fn test_array_reset() {
        let arr = array![1, 2, 3];
        let reset_arr = ArrayGResettable::g_reset(arr);
        assert(reset_arr.len() == 0_u32, 'Array should be empty');
    }

    #[test]
    fn test_g_convert_creation() {
        let _ = g_convertTrait::new(42_felt252);
        let _ = g_convertTrait::new(255_u8);
        let _ = g_convertTrait::new(true);
        let _ = g_convertTrait::new("Hello");
    }

    #[test]
    fn test_felt252_conversion() {
        let dynamic = g_convertTrait::new(42_felt252);
        let converted: felt252 = g_convertTrait::g_convert(dynamic);
        assert(converted == 42_felt252, 'Felt252 conversion failed');
    }

    #[test]
    fn test_u8_to_felt252() {
        let dynamic = g_convertTrait::new(100_u8);
        let converted: felt252 = g_convertTrait::g_convert(dynamic);
        assert(converted == 100_felt252, 'U8 to felt252 failed');
    }

    #[test]
    fn test_bool_conversion() {
        let dynamic = g_convertTrait::new(true);
        let converted: bool = g_convertTrait::g_convert(dynamic);
        assert(converted == true, 'Bool conversion failed');
    }

    #[test]
    fn test_to_string() {
        let felt_val = g_convertTrait::new(123_felt252);
        assert(felt_val.to_string() == "123", 'Felt252 to string failed');

        let bool_val = g_convertTrait::new(false);
        assert(bool_val.to_string() == "false", 'Bool to string failed');
    }

    #[test]
    fn test_contract_address_conversion() {
        let addr = contract_address_const::<0xabc>();
        let dynamic = g_convertTrait::new(addr);
        let converted: ContractAddress = g_convertTrait::g_convert(dynamic);
        assert(converted == addr, 'Address conversion failed');
    }

    #[test]
    fn test_numeric_to() {
        let val1 = g_convertTrait::new(50_felt252);
        let val2 = g_convertTrait::new(10_u8);
        assert(val1.to(val2) == 50_felt252, 'to() failed');
    }

    #[test]
    fn test_roundtrip_bytearray() {
        let original: ByteArray = "Test";
        let wrapped = g_convertTrait::new(original.clone());
        let unwrapped: ByteArray = g_convertTrait::g_convert(wrapped);
        assert(unwrapped == original, 'ByteArray roundtrip failed');
    }
}