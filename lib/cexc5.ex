defmodule Cexc5 do
  use Bitwise
  @moduledoc """
    Create custom configured CRC calculation functions
  """

  @doc """
    Returns a list containing 1 and 2 arity CRC calculation functions
    and a CRC look-up table

    Example: ```
      # Use a preconfigured CRC algorithm
      [crc1_fn, _crc2_fn, _table] = Cexc.init("CRC16_AUG_CCIT")

      # Generate a CRC for a list of bytes
      0xE5CC = crc1_fn.('123456789')

      # Check that a list of bytes has been received without errors
      crc1_fn.([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xE5,0xCC]) == 0

      # manually specify CRC algorithm parameters
      # use the form: {bits, polynomial, init_value, final_xor_value, reflected?}
      [crc1_fn, _crc2_fn, _table] = Cexc.init({16, 0x1234, 0, 0, true})

      0xF13 = crc1_fn.('123456789')
      crc1_fn.([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x13,0x0F]) == 0
    ```
  """
  @spec init (string.t() | tuple()) :: list()
  def init(crc_def) do
    {bits, polynomial, init_value, final_xor_value, reflected} =
      case is_binary(crc_def) do
        true -> name_to_config(crc_def)
        false -> crc_def
      end

    table = gen_table(bits, polynomial, reflected)

    gen_crc_funs(bits, table, init_value, final_xor_value, reflected)
  end

  # Generate 8-bit CRC functions.
  # Functions are same for normal and reflected cases
  defp gen_crc_funs(8, table, init_value, final_xor_value, _reflected) do

    crc2_fn = fn kldfsdkls
      (cur_crc, [cur_byte | rem]) ->
        index = cur_crc ^^^ cur_byte
        next_crc = elem(table, index)
        kldfsdkls.(next_crc, rem)

      (cur_crc, []) -> cur_crc ^^^ final_xor_value
    end

    crc1_fn = fn (data) -> crc2_fn.(init_value, data) end

    [crc1_fn, crc2_fn, table]
  end

  # Generate 16, 32, or 64-bit CRC functions for un-reflected case
  defp gen_crc_funs(bits, table, init_value, final_xor_value, false) do
    shift = bits_to_shift(bits)
    mask = bits_to_mask(bits)

    crc2_fn = fn
      (cur_crc, [cur_byte | rem]) ->
        index = (cur_crc >>> shift) ^^^ cur_byte &&& 0xFF
        next_crc = (cur_crc <<< 8) ^^^ elem(table, index) &&& mask
        .(next_crc, rem)

      (cur_crc, []) -> cur_crc ^^^ final_xor_value
    end

    crc1_fn = fn (data) -> crc2_fn.(init_value, data) end

    [crc1_fn, crc2_fn, table]
  end

  # Generate 16, 32, or 64-bit CRC functions for reflected case
  defp gen_crc_funs(bits, table, init_value, final_xor_value, true) do
    mask = bits_to_mask(bits)

    crc2_fn = fn
      (cur_crc, [cur_byte | rem]) ->
        index = cur_crc ^^^ cur_byte &&& 0xFF
        next_crc = (cur_crc >>> 8) ^^^ elem(table, index) &&& mask
        .(next_crc, rem)

      (cur_crc, []) -> cur_crc ^^^ final_xor_value
    end

    crc1_fn = fn (data) -> crc2_fn.(init_value, data) end

    [crc1_fn, crc2_fn, table]
  end

  # Generate CRC look-up table for un-reflected and reflected cases
  defp gen_table(bits, polynomial, false) do
    hi_bit = bits_to_hibit(bits)
    mask = bits_to_mask(bits)
    shift = bits_to_shift(bits)
    gen_table(hi_bit, mask, shift, polynomial, [], 0)
  end

  defp gen_table(bits, polynomial, true) do
    polynomial_r = reflect(bits, polynomial)
    mask = bits_to_mask(bits)
    gen_table_r(mask, polynomial_r, [], 0)
  end

  # Generate un-reflected CRC lookup table
  defp gen_table(_hi_bit, _mask, _shift, _polynomial, table, 256) do
    List.to_tuple(Enum.reverse(table))
  end

  defp gen_table(hi_bit, mask, shift, polynomial, table, divident) do
    curr_byte = curr_byte(hi_bit, polynomial, divident <<< shift, 0)
    gen_table(hi_bit, mask, shift, polynomial, [curr_byte &&& mask | table], divident + 1)
  end

  defp curr_byte(_hi_bit, _polynomial, curr_byte, 8), do: curr_byte

  defp curr_byte(hi_bit, polynomial, curr_byte, index) do
    next_byte =
      case curr_byte &&& hi_bit do
        0 -> curr_byte <<< 1
        _ -> (curr_byte <<< 1) ^^^ polynomial
      end

    curr_byte(hi_bit, polynomial, next_byte, index + 1)
  end

  # Generate reflected CRC lookup table
  defp gen_table_r(_mask, _polynomial, table, 256) do
    List.to_tuple(Enum.reverse(table))
  end

  defp gen_table_r(mask, polynomial, table, divident) do
    curr_byte = curr_byte_r(polynomial, divident, 0)
    gen_table_r(mask, polynomial, [curr_byte &&& mask | table], divident + 1)
  end

  defp curr_byte_r(_polynomial, curr_byte, 8), do: curr_byte

  defp curr_byte_r(polynomial, curr_byte, index) do
    next_byte =
      case curr_byte &&& 1 do
        0 -> curr_byte >>> 1
        1 -> (curr_byte >>> 1) ^^^ polynomial
      end

    curr_byte_r(polynomial, next_byte, index + 1)
  end

  # Convert CRC name to config parameters
  defp name_to_config("CRC8"), do: {8, 0x07, 0x00, 0x00, false}
  defp name_to_config("CRC8_SAE_J1850"), do: {8, 0x1D, 0xFF, 0xFF, false}
  defp name_to_config("CRC8_SAE_J1850_ZERO"), do: {8, 0x1D, 0x00, 0x00, false}
  defp name_to_config("CRC8_8H2F"), do: {8, 0x2F, 0xFF, 0xFF, false}
  defp name_to_config("CRC8_CDMA2000"), do: {8, 0x9B, 0xFF, 0x00, false}
  defp name_to_config("CRC8_DARC"), do: {8, 0x39, 0x00, 0x00, true}
  defp name_to_config("CRC8_DVB_S2"), do: {8, 0xD5, 0x00, 0x00, false}
  defp name_to_config("CRC8_EBU"), do: {8, 0x1D, 0xFF, 0x00, true}
  defp name_to_config("CRC8_ICODE"), do: {8, 0x1D, 0xFD, 0x00, false}
  defp name_to_config("CRC8_ITU"), do: {8, 0x07, 0x00, 0x55, false}
  defp name_to_config("CRC8_MAXIM"), do: {8, 0x31, 0x00, 0x00, true}
  defp name_to_config("CRC8_ROHC"), do: {8, 0x07, 0xFF, 0x00, true}
  defp name_to_config("CRC8_WCDMA"), do: {8, 0x9B, 0x00, 0x00, true}
  defp name_to_config("CRC16_CCIT_ZERO"), do: {16, 0x1021, 0x0000, 0x0000, false}
  defp name_to_config("CRC16_ARC"), do: {16, 0x8005, 0x0000, 0x0000, true}
  defp name_to_config("CRC16_AUG_CCITT"), do: {16, 0x1021, 0x1D0F, 0x0000, false}
  defp name_to_config("CRC16_BUYPASS"), do: {16, 0x8005, 0x0000, 0x0000, false}
  defp name_to_config("CRC16_CCITT_FALSE"), do: {16, 0x1021, 0xFFFF, 0x0000, false}
  defp name_to_config("CRC16_CDMA2000"), do: {16, 0xC867, 0xFFFF, 0x0000, false}
  defp name_to_config("CRC16_DDS_110"), do: {16, 0x8005, 0x800D, 0x0000, false}
  defp name_to_config("CRC16_DECT_R"), do: {16, 0x0589, 0x0000, 0x0001, false}
  defp name_to_config("CRC16_DECT_X"), do: {16, 0x0589, 0x0000, 0x0000, false}
  defp name_to_config("CRC16_DNP"), do: {16, 0x3D65, 0x0000, 0xFFFF, true}
  defp name_to_config("CRC16_EN_13757"), do: {16, 0x3D65, 0x0000, 0xFFFF, false}
  defp name_to_config("CRC16_GENIBUS"), do: {16, 0x1021, 0xFFFF, 0xFFFF, false}
  defp name_to_config("CRC16_MAXIM"), do: {16, 0x8005, 0x0000, 0xFFFF, true}
  defp name_to_config("CRC16_MCRF4XX"), do: {16, 0x1021, 0xFFFF, 0x0000, true}
  defp name_to_config("CRC16_RIELLO"), do: {16, 0x1021, 0xB2AA, 0x0000, true}
  defp name_to_config("CRC16_T10_DIF"), do: {16, 0x8BB7, 0x0000, 0x0000, false}
  defp name_to_config("CRC16_TELEDISK"), do: {16, 0xA097, 0x0000, 0x0000, false}
  defp name_to_config("CRC16_TMS37157"), do: {16, 0x1021, 0x89EC, 0x0000, true}
  defp name_to_config("CRC16_USB"), do: {16, 0x8005, 0xFFFF, 0xFFFF, true}
  defp name_to_config("CRC16_A"), do: {16, 0x1021, 0xC6C6, 0x0000, true}
  defp name_to_config("CRC16_KERMIT"), do: {16, 0x1021, 0x0000, 0x0000, true}
  defp name_to_config("CRC16_MODBUS"), do: {16, 0x8005, 0xFFFF, 0x0000, true}
  defp name_to_config("CRC16_X_25"), do: {16, 0x1021, 0xFFFF, 0xFFFF, true}
  defp name_to_config("CRC16_XMODEM"), do: {16, 0x1021, 0x0000, 0x0000, false}
  defp name_to_config("CRC32"), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config("CRC32_BZIP2"), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, false}
  defp name_to_config("CRC32_C"), do: {32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config("CRC32_D"), do: {32, 0xA833982B, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config("CRC32_MPEG2"), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, false}
  defp name_to_config("CRC32_POSIX"), do: {32, 0x04C11DB7, 0x00000000, 0xFFFFFFFF, false}
  defp name_to_config("CRC32_Q"), do: {32, 0x814141AB, 0x00000000, 0x00000000, false}
  defp name_to_config("CRC32_JAMCRC"), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, true}
  defp name_to_config("CRC32_XFER"), do: {32, 0x000000AF, 0x00000000, 0x00000000, false}
  defp name_to_config("CRC64_ECMA_182"), do: {64, 0x42F0E1EBA9EA3693, 0x0, 0x0, false}

  defp name_to_config("CRC64_GO_ISO"),
    do: {64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true}

  defp name_to_config("CRC64_WE"),
    do: {64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, false}

  defp name_to_config("CRC64_XZ"),
    do: {64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true}

  #
  # Utility functions
  #

  defp reflect(bits, value), do: reflect(bits, value, 0, 0)

  defp reflect(bits, _value, result, index) when index == bits, do: result

  defp reflect(bits, value, result, index) do
    next_result =
      case value &&& 1 <<< index do
        0 -> result
        _ -> result ||| 1 <<< (bits - 1 - index)
      end

    reflect(bits, value, next_result, index + 1)
  end

  defp bits_to_mask(bits), do: (1 <<< bits) - 1

  defp bits_to_hibit(bits), do: 1 <<< (bits - 1)

  defp bits_to_shift(bits), do: bits - 8
end
