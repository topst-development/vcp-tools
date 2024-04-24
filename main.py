import os
import sys
import struct
#import hashlib
import SHA256Context
import zlib
from crc_table import CRC32_TABLE
from hsm import hsm_data
from updater import updater_data

# Constants similar to the ones defined in your header file
MICOM_ROM_HEADER_SIZE = 0x1000
MICOM_UPDATER_AREA_SIZE = 192 * 1024
MICOM_HEADER_OFFSET = 0x42000
ALIGN_SIZE = 4
SFMC_INIT_HEAD_SIZE = 1024 * 2
SFMC_INIT_HEAD_REAL_SIZE = 256
EF_INIT_HEAD_SIZE = 2048
EF_INIT_HEAD_REAL_SIZE = 64
EF_INIT_HEAD0_OFFSET = 0  # Placeholder, set the actual offset
SFQPI_INIT_HEAD_REAL_SIZE = 256

CODE_def_EFLASH = {
    "signature": 0x534C4665, # "eFLS"
    "valid_n": 0xFFFFFFFC,
    "DCYCRDCON": 0x001E0002,
    "DCYCWRCON": 0x00020100,
    "EXTCON0": 0xFFFFFFFF,
    "RSTCNT": 0xFFFFFFFF,
    "EFLASH_CLKCHG": 0xFFFFFFFF,
    "reserved": [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
    "CRC": 0x04000000,
}

CODE_4READ3B = {
    "code": 0x000000E0,
    "timing": 0x00040310,
    "delay_so": 0x00000500,
    "dc_clk": 0x00001515,
    "dc_wbd0": 0x00000000,
	"dc_wbd1": 0x00000000,
	"dc_rbd0": 0x00000000,
	"dc_rbd1": 0x00000000,
	"dc_woebd0": 0x00000000,
	"dc_woebd1": 0x00000000,
	"dc_base_addr_manu_0": 0x00000818,
	"dc_base_addr_manu_1": 0x0000081C,
	"dc_base_addr_auto": 0x00000800,
	"run_mode": 0x00000001,
	"reserved": [0x00000000, 0x00000000, 0x00000000],
	"code_vlu": [0x840000EB, 0x4A000001, 0x86000000, 0x46002000, 
              0x2A000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xA4000006, 0xF4000000, 0x84000001, 0xA4000040, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000, 0xF4000000, 0xF4000000, 
              0xF4000000, 0xF4000000 ],
    "crc": 0x00000077,
}

def calculate_crc8(data):
    """Calculate CRC32 based on the provided CRC32_TABLE."""
    crcout = 0
    # count = 0
    for byte in data:
        tmp = byte ^ crcout
        crcout = (crcout >> 8) ^ CRC32_TABLE[tmp & 0xFF]
        # if count > len(data) - 10:
        #     print(f"count: {count}, byte: {byte:02x}, tmp: {tmp:08x}, crcout: {crcout:08x}")
        # count += 1
    return crcout

def EFLASH_MIO_BOOT_Write_Header(rom_file_buffer):
    """Simulate the EFLASH MIO BOOT Write Header function."""
    # Initialize the header structure with zeros (assuming size from C structure)
    header = bytearray(EF_INIT_HEAD_REAL_SIZE)
    
    # fill the header with 0xff
    header.zfill(EF_INIT_HEAD_REAL_SIZE)

    # Packing data into the bytearray
    signature = CODE_def_EFLASH["signature"]
    valid_n = CODE_def_EFLASH["valid_n"]
    DCYCRDCON = CODE_def_EFLASH["DCYCRDCON"]
    DCYCWRCON = CODE_def_EFLASH["DCYCWRCON"]
    EXTCON0 = CODE_def_EFLASH["EXTCON0"]
    RSTCNT = CODE_def_EFLASH["RSTCNT"]
    EFLASH_CLKCHG = CODE_def_EFLASH["EFLASH_CLKCHG"]
    crc = CODE_def_EFLASH["CRC"]
    
    struct.pack_into('<I', header, 0, signature)
    struct.pack_into('<I', header, 4, valid_n)
    struct.pack_into('<I', header, 8, DCYCRDCON)
    struct.pack_into('<I', header, 12, DCYCWRCON)
    struct.pack_into('<I', header, 16, EXTCON0)
    struct.pack_into('<I', header, 20, RSTCNT)
    struct.pack_into('<I', header, 24, EFLASH_CLKCHG)
    for i in range(8):
        struct.pack_into('<I', header, 28 + i * 4, CODE_def_EFLASH["reserved"][i])
    struct.pack_into('<I', header, len(header) - 4, crc)

    # Calculate CRC
    crc = calculate_crc8(header[:EF_INIT_HEAD_REAL_SIZE][:-4])
    # Update the CRC field
    struct.pack_into('<I', header, len(header) - 4, crc)
    
    # printout signature, valid_n, DCYCRDCON, DCYCWRCON, EXTCON0, RSTCNT, EFLASH_CLKCHG, reserved, CRC
    print(f"signature: {signature:08x}")
    print(f"valid_n: {valid_n:08x}")
    print(f"DCYCRDCON: {DCYCRDCON:08x}")
    print(f"DCYCWRCON: {DCYCWRCON:08x}")
    print(f"EXTCON0: {EXTCON0:08x}")
    print(f"RSTCNT: {RSTCNT:08x}")
    print(f"EFLASH_CLKCHG: {EFLASH_CLKCHG:08x}")
    print(f"reserved: {CODE_def_EFLASH['reserved']}")
    print(f"CRC: {crc:08x}")
    
    rom_file_buffer[:len(header)] = header
    return 0

def SNOR_MIO_BOOT_Write_Header(rom_file_buffer, offset=EF_INIT_HEAD_SIZE):
    """Build the SNOR MIO BOOT Header function."""
    # Initialize the header structure with zeros (assuming size from C structure)
    header = bytearray(SFQPI_INIT_HEAD_REAL_SIZE)
    
    # fill the header with 0xff
    header.zfill(SFQPI_INIT_HEAD_REAL_SIZE)

    # Packing data into the bytearray
    code = CODE_4READ3B["code"]
    timing = CODE_4READ3B["timing"]
    delay_so = CODE_4READ3B["delay_so"]
    dc_clk = CODE_4READ3B["dc_clk"]
    dc_wbd0 = CODE_4READ3B["dc_wbd0"]
    dc_wbd1 = CODE_4READ3B["dc_wbd1"]
    dc_rbd0 = CODE_4READ3B["dc_rbd0"]
    dc_rbd1 = CODE_4READ3B["dc_rbd1"]
    dc_woebd0 = CODE_4READ3B["dc_woebd0"]
    dc_woebd1 = CODE_4READ3B["dc_woebd1"]
    dc_base_addr_manu_0 = CODE_4READ3B["dc_base_addr_manu_0"]
    dc_base_addr_manu_1 = CODE_4READ3B["dc_base_addr_manu_1"]
    dc_base_addr_auto = CODE_4READ3B["dc_base_addr_auto"]
    run_mode = CODE_4READ3B["run_mode"]
    reserved = CODE_4READ3B["reserved"]
    code_vlu = CODE_4READ3B["code_vlu"]
    crc = CODE_4READ3B["crc"]
    
    struct.pack_into('<I', header, 0, code)
    struct.pack_into('<I', header, 4, timing)
    struct.pack_into('<I', header, 8, delay_so)
    struct.pack_into('<I', header, 12, dc_clk)
    struct.pack_into('<I', header, 16, dc_wbd0)
    struct.pack_into('<I', header, 20, dc_wbd1)
    struct.pack_into('<I', header, 24, dc_rbd0)
    struct.pack_into('<I', header, 28, dc_rbd1)
    struct.pack_into('<I', header, 32, dc_woebd0)
    struct.pack_into('<I', header, 36, dc_woebd1)
    struct.pack_into('<I', header, 40, dc_base_addr_manu_0)
    struct.pack_into('<I', header, 44, dc_base_addr_manu_1)
    struct.pack_into('<I', header, 48, dc_base_addr_auto)
    struct.pack_into('<I', header, 52, run_mode)
    for i in range(3):
        struct.pack_into('<I', header, 56 + i * 4, reserved[i])
    for i in range(46):
        struct.pack_into('<I', header, 68 + i * 4, code_vlu[i])
    struct.pack_into('<I', header, len(header) - 4, crc)

    # Calculate CRC
    crc = calculate_crc8(header[:SFQPI_INIT_HEAD_REAL_SIZE][:-4])
    # Update the CRC field
    struct.pack_into('<I', header, len(header) - 4, crc)
    
    # printout all fields on the header
    print(f"code: {code:08x}")
    print(f"timing: {timing:08x}")
    print(f"delay_so: {delay_so:08x}")
    print(f"dc_clk: {dc_clk:08x}")
    print(f"read command: {code_vlu[:5]}")
    print(f"CMD CRC: {crc:08x}")
    
    rom_file_buffer[offset:offset+len(header)] = header
    return 0

def write_pflash_init_header(file_path):
    """Write the combined EFLASH and SNOR headers to a file."""
    headers_buf = bytearray([0xff] * (SFMC_INIT_HEAD_SIZE * 2))  # Buffer to hold all header data
       
    # Call the header functions
    if EFLASH_MIO_BOOT_Write_Header(headers_buf) != 0:
        return False
    print("EFLASH header written successfully")
    print(f"Header buffer: {len(headers_buf)}")
    if SNOR_MIO_BOOT_Write_Header(headers_buf) != 0:
         return False
    print("SNOR header written successfully")
    print(f"Header buffer: {len(headers_buf)}")
    
    # Write to file
    with open(file_path, 'wb') as f:
        f.seek(EF_INIT_HEAD0_OFFSET)
        ret_size = f.write(headers_buf)
        if ret_size != len(headers_buf):
            print("File write failed")
            return False
        else:
            print(f"File written successfully: {ret_size} bytes to {f}")
            
        # Write the second header
        ret_size = f.write(headers_buf)
        if ret_size != len(headers_buf):
            print("File write failed")
            return False
        else:
            print(f"File written successfully: {ret_size} bytes to {f}")

    return True

def read_binary_file(filepath):
    """Read the entire content of a binary file."""
    with open(filepath, 'rb') as file:
        return file.read()

def write_binary_file(filepath, data):
    """Write data to a binary file."""
    with open(filepath, 'wb') as file:
        file.write(data)

def get_file_size(filepath):
    """Get the size of the file."""
    return os.path.getsize(filepath)

def calculate_crc32(data):
    """Calculate the CRC32 checksum of the given data."""
    return zlib.crc32(data) & 0xffffffff

def align_data(data, alignment=ALIGN_SIZE):
    """Align data to the specified boundary."""
    padding_size = (alignment - len(data) % alignment) % alignment
    return data + (b'\xff' * padding_size)

# Constants
IMAGE_NAME_MAX_SIZE = 12
IMAGE_VERSION_MAX_SIZE = 16
ALIGN_SIZE = 64
IMAGE_FOOTER_SIZE = 128  # Assuming the footer is 128 bytes in size
BODY_OFFSET = 0x1000

def align_size(length, alignment):
    return (length + (alignment - 1)) & ~(alignment - 1)

def fill_dummy_cert(outputfile):
    dummy_cert = b'CERT' + bytes(252)  # 252 zero bytes
    outputfile.write(dummy_cert)

def fill_dummy_footer(outputfile):
    dummy_footer = bytes(128)  # 128 zero bytes
    outputfile.write(dummy_footer)

def calc_hash(inputfile):
    ctx = SHA256Context.SHA256Context()
    inputfile.seek(0)  # Reset file pointer to the beginning
    while True:
        data = inputfile.read(ALIGN_SIZE)
        if not data:
            break
        ctx.update(data)
        # print(f"{data.hex()} -> {ctx['h0']:08x}") #{ctx['h1']:08x}{ctx['h2']:08x}{ctx['h3']:08x}{ctx['h4']:08x}{ctx['h5']:08x}{ctx['h6']:08x}{ctx['h7']:08x}")
    inputfile.seek(0)  # Reset file pointer to the beginning for further use
    return ctx.digest()

def fill_header(outputfile, inputfile, image_name, image_version, target_address, soc_name):
    body_length = os.path.getsize(inputfile.name)
    aligned_body_length = align_size(body_length, ALIGN_SIZE) + IMAGE_FOOTER_SIZE
    body_hash = calc_hash(inputfile)
    reserved1 = b'\x00\x00\x00\x00'  # Four reserved bytes
    reserved2 = bytes(40)  # 40 reserved bytes
    reserved3 = bytes(128)  # 128 reserved bytes for Sign Tool

    # Packing the header with all the information
    header_format = '<4sII4s4s12s16sQ40s32s128s'
    header = struct.pack(header_format, b'HDR\0', 
                         aligned_body_length, 
                         BODY_OFFSET,
                         reserved1, 
                         soc_name.encode('utf-8'), 
                         image_name.encode('utf-8')[:IMAGE_NAME_MAX_SIZE], 
                         image_version.encode('utf-8')[:IMAGE_VERSION_MAX_SIZE],
                         int(target_address, 16), 
                         reserved2, 
                         body_hash, 
                         reserved3)
    
    outputfile.write(header)
    # fill the offset with zeros
    outputfile.write(bytes(BODY_OFFSET - outputfile.tell()))

def print_header_info(marker, body_length, body_offset, soc_name, image_name, image_version, target_address, body_hash):
    print("Header Information:")
    print(f"Marker: {marker.decode('utf-8')}")
    print(f"Body Length: {body_length}")
    print(f"Body Offset: {body_offset}")
    print(f"SOC Name: {soc_name.decode('utf-8')}")
    print(f"Image Name: {image_name.decode('utf-8').strip()}")
    print(f"Image Version: {image_version.decode('utf-8').strip()}")
    print(f"Target Address: {hex(target_address)}")
    print(f"Body Hash: {body_hash.hex()}")
    print()

def make_image(inputfile, outputfile, image_name, image_version, target_address, soc_name):
    fill_dummy_cert(outputfile)
    fill_header(outputfile, inputfile, image_name, image_version, target_address, soc_name)
    # write the body of the image
    # it must be aligned to 64 bytes
    data = inputfile.read()
    data_length = len(data)
    remain_length = ALIGN_SIZE - (data_length % ALIGN_SIZE)
    outputfile.write(data)
    # fill the rest of the body with zeros
    outputfile.write(bytes(remain_length))
    # fill the footer with zeros    
    fill_dummy_footer(outputfile)
    return 0

def print_help():
    print("\nTelechips Image Maker")
    print("Usage(windows): tcmk-convert <input_file> <output_file>")
    print("Example: tcmk-convert input.bin output.rom")

def main():
    if len(sys.argv) < 3:
        print_help()
        return -1

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    image_name = "R5-FW"
    image_version = "0.0.1"
    target_address = "0x00000000"
    soc_name = "70xx"
    intermed_file = "r5_fw.rom"

    print(f"Input File: {input_file}")
    print(f"Intermediate File: {intermed_file}")
    print(f"Output File: {output_file}")
    print(f"Image Name: {image_name}")
    print(f"Image Version: {image_version}")
    print(f"Target Address: {target_address}")
    print(f"SOC Name: {soc_name}")
    
    try:
        with open(input_file, 'rb') as inputfile, open(intermed_file, 'wb') as intermed_file:
            result = make_image(inputfile, intermed_file, image_name, image_version, target_address, soc_name)
            if result == 0:
                print(f"{intermed_file} was generated successfully")
            else:
                print(f"ERROR: output file generation error (error code: {result})")
    except Exception as e:
        print(f"ERROR: {str(e)}")

    input_files = {
        'micom_rom': 'r5_fw.rom',
        'updater': 'updater.rom',
        'hsm': 'hsm.bin',
        'output': 'tcc70xx_pflash_boot.rom'
    }

    write_pflash_init_header(output_file)
    
    #file_data = read_binary_file('hsm.bin')
    # convert hsm_data to bytes
    file_data = bytes(hsm_data)
    # enlarge the file to 128KB
    file_data = align_data(file_data, 128 * 1024)

    with open(output_file, 'ab') as f: # Open the file in binary mode
        # Append the HSM binary data to the file
        f.seek(0, 2) # Seek to the end of the file
        # print current file position
        print(f"Write HSM bin(0) at: {hex(f.tell())}, length: {len(file_data)}")
        f.write(file_data)
        print(f"Write HSM bin(1) at: {hex(f.tell())}, length: {len(file_data)}")
        f.write(file_data)
    print("HSM binary data appended successfully.")
    print(f"File size: {get_file_size(output_file):,} bytes")
    
    file_data = read_binary_file(input_files['micom_rom'])
    micom_len = len(file_data)
    with open(output_file, 'ab') as f:
        f.seek(MICOM_HEADER_OFFSET, 0) # Seek to the predefined offset
        f.write(file_data)

    # Align micom_len with 0x10
    aligned_micom_len = (micom_len + 0xf) & ~0xf
    
    # Append the updater binary data to the file
    # file_data = read_binary_file(input_files['updater'])
    file_data = bytes(updater_data)
    # enlarge the file to 192KB
    file_data = align_data(file_data, 192 * 1024)
    
    with open(output_file, 'ab') as f:
        f.seek(MICOM_HEADER_OFFSET + aligned_micom_len, 0) # Seek to the predefined offset
        f.write(file_data)
    
    print("Image created successfully.")

if __name__ == "__main__":
    main()
