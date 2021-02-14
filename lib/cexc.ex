defmodule Cexc do
  use Bitwise

  @moduledoc """
    Generate custom configured, Cyclic Redundancy Check (CRC) calculation functions
  """

  defstruct [:bits, :reducer, :init_value, :final_xor_value]

  @type t() :: %__MODULE__{
          bits: 8 | 16 | 32 | 64,
          reducer: fun(),
          init_value: non_neg_integer(),
          final_xor_value: non_neg_integer()
        }

  @doc """
    init/1 Returns struct containing CRC calculation function
    and associated configuration values

    Example: ```
      # Use a preconfigured CRC algorithm
      crc16 = Cexc.init(:crc16_aug_ccitt)

      # Generate a CRC for a list of bytes
      0xE5CC = Cexc.calc_crc('123456789', crc16)

      # Check that a list of bytes has been received without errors
      Cexc.calc_crc([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xE5,0xCC], crc16) == 0

      # manually specify CRC algorithm parameters
      # use the form: {bits, polynomial, init_value, final_xor_value, reflected?}
      custom_crc = Cexc.init({16, 0x1234, 0, 0, true})

      0xF13 = Cexc.calc_crc('123456789', custom_crc)
      Cexc.calc_crc([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x13,0x0F], custom_crc) == 0
    ```
  """
  @spec init(atom() | tuple()) :: t()
  def init(crc_def) when is_atom(crc_def) do
    init(name_to_config(crc_def))
  end

  def init({8, polynomial, init_value, final_xor_value, reflected}) do
    table = gen_table(8, polynomial, reflected)

    %__MODULE__{
      bits: 8,
      init_value: init_value,
      final_xor_value: final_xor_value,
      reducer: fn cur_byte, cur_crc ->
        index = cur_crc ^^^ cur_byte
        elem(table, index)
      end
    }
  end

  def init({bits, polynomial, init_value, final_xor_value, false}) when bits in [16, 32, 64] do
    table = gen_table(bits, polynomial, false)
    shift = bits_to_shift(bits)
    mask = bits_to_mask(bits)

    %__MODULE__{
      bits: bits,
      init_value: init_value,
      final_xor_value: final_xor_value,
      reducer: fn cur_byte, cur_crc ->
        index = (cur_crc >>> shift) ^^^ cur_byte &&& 0xFF
        (cur_crc <<< 8) ^^^ elem(table, index) &&& mask
      end
    }
  end

  def init({bits, polynomial, init_value, final_xor_value, true}) when bits in [16, 32, 64] do
    table = gen_table(bits, polynomial, true)
    mask = bits_to_mask(bits)

    %__MODULE__{
      bits: bits,
      init_value: init_value,
      final_xor_value: final_xor_value,
      reducer: fn cur_byte, cur_crc ->
        index = cur_crc ^^^ cur_byte &&& 0xFF
        (cur_crc >>> 8) ^^^ elem(table, index) &&& mask
      end
    }
  end

  @doc """
    Calculates the CRC of the list of data bytes
  """
  @spec calc_crc(list(), Cexc6.t()) :: non_neg_integer()
  def calc_crc(data, %__MODULE__{} = info) when is_list(data) do
    data
    |> Enum.reduce(info.init_value, info.reducer)
    |> Bitwise.bxor(info.final_xor_value)
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
  defp name_to_config(:crc8), do: {8, 0x07, 0x00, 0x00, false}
  defp name_to_config(:crc8_sae_j1850), do: {8, 0x1D, 0xFF, 0xFF, false}
  defp name_to_config(:crc8_sae_j1850_zero), do: {8, 0x1D, 0x00, 0x00, false}
  defp name_to_config(:crc8_8h2f), do: {8, 0x2F, 0xFF, 0xFF, false}
  defp name_to_config(:crc8_cdma2000), do: {8, 0x9B, 0xFF, 0x00, false}
  defp name_to_config(:crc8_darc), do: {8, 0x39, 0x00, 0x00, true}
  defp name_to_config(:crc8_dvb_s2), do: {8, 0xD5, 0x00, 0x00, false}
  defp name_to_config(:crc8_ebu), do: {8, 0x1D, 0xFF, 0x00, true}
  defp name_to_config(:crc8_icode), do: {8, 0x1D, 0xFD, 0x00, false}
  defp name_to_config(:crc8_itu), do: {8, 0x07, 0x00, 0x55, false}
  defp name_to_config(:crc8_maxim), do: {8, 0x31, 0x00, 0x00, true}
  defp name_to_config(:crc8_sensirion), do: {8, 0x31, 0xFF, 0x00, false}
  defp name_to_config(:crc8_rohc), do: {8, 0x07, 0xFF, 0x00, true}
  defp name_to_config(:crc8_wcdma), do: {8, 0x9B, 0x00, 0x00, true}
  defp name_to_config(:crc16_ccitt_zero), do: {16, 0x1021, 0x0000, 0x0000, false}
  defp name_to_config(:crc16_arc), do: {16, 0x8005, 0x0000, 0x0000, true}
  defp name_to_config(:crc16_aug_ccitt), do: {16, 0x1021, 0x1D0F, 0x0000, false}
  defp name_to_config(:crc16_buypass), do: {16, 0x8005, 0x0000, 0x0000, false}
  defp name_to_config(:crc16_ccitt_false), do: {16, 0x1021, 0xFFFF, 0x0000, false}
  defp name_to_config(:crc16_cdma2000), do: {16, 0xC867, 0xFFFF, 0x0000, false}
  defp name_to_config(:crc16_dds_110), do: {16, 0x8005, 0x800D, 0x0000, false}
  defp name_to_config(:crc16_dect_r), do: {16, 0x0589, 0x0000, 0x0001, false}
  defp name_to_config(:crc16_dect_x), do: {16, 0x0589, 0x0000, 0x0000, false}
  defp name_to_config(:crc16_dnp), do: {16, 0x3D65, 0x0000, 0xFFFF, true}
  defp name_to_config(:crc16_en_13757), do: {16, 0x3D65, 0x0000, 0xFFFF, false}
  defp name_to_config(:crc16_genibus), do: {16, 0x1021, 0xFFFF, 0xFFFF, false}
  defp name_to_config(:crc16_maxim), do: {16, 0x8005, 0x0000, 0xFFFF, true}
  defp name_to_config(:crc16_mcrf4xx), do: {16, 0x1021, 0xFFFF, 0x0000, true}
  defp name_to_config(:crc16_riello), do: {16, 0x1021, 0xB2AA, 0x0000, true}
  defp name_to_config(:crc16_t10_dif), do: {16, 0x8BB7, 0x0000, 0x0000, false}
  defp name_to_config(:crc16_teledisk), do: {16, 0xA097, 0x0000, 0x0000, false}
  defp name_to_config(:crc16_tms37157), do: {16, 0x1021, 0x89EC, 0x0000, true}
  defp name_to_config(:crc16_usb), do: {16, 0x8005, 0xFFFF, 0xFFFF, true}
  defp name_to_config(:crc16_a), do: {16, 0x1021, 0xC6C6, 0x0000, true}
  defp name_to_config(:crc16_kermit), do: {16, 0x1021, 0x0000, 0x0000, true}
  defp name_to_config(:crc16_modbus), do: {16, 0x8005, 0xFFFF, 0x0000, true}
  defp name_to_config(:crc16_x_25), do: {16, 0x1021, 0xFFFF, 0xFFFF, true}
  defp name_to_config(:crc16_xmodem), do: {16, 0x1021, 0x0000, 0x0000, false}
  defp name_to_config(:crc32), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config(:crc32_bzip2), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, false}
  defp name_to_config(:crc32_c), do: {32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config(:crc32_d), do: {32, 0xA833982B, 0xFFFFFFFF, 0xFFFFFFFF, true}
  defp name_to_config(:crc32_mpeg2), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, false}
  defp name_to_config(:crc32_posix), do: {32, 0x04C11DB7, 0x00000000, 0xFFFFFFFF, false}
  defp name_to_config(:crc32_q), do: {32, 0x814141AB, 0x00000000, 0x00000000, false}
  defp name_to_config(:crc32_jamcrc), do: {32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, true}
  defp name_to_config(:crc32_xfer), do: {32, 0x000000AF, 0x00000000, 0x00000000, false}
  defp name_to_config(:crc64_ecma_182), do: {64, 0x42F0E1EBA9EA3693, 0x0, 0x0, false}

  defp name_to_config(:crc64_go_iso),
    do: {64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true}

  defp name_to_config(:crc64_we),
    do: {64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, false}

  defp name_to_config(:crc64_xz),
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
