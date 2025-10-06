#!/usr/bin/env python3
"""
This script uses aggressive steganography techniques:
- Uses 4 LSBs per color channel (12 bits per pixel)
- Automatically resizes images to fit large data files
- Supports JPEG and PNG input images
- Output is saved as PNG to preserve data integrity
- Image quality will be significantly altered for large data files
"""
import os
import sys
import struct
import hashlib
from PIL import Image
import numpy as np


magic_header = b'X9K7Q2M8'  # Update this as needed

def embed_data_in_image(image_path, data_path, output_path):
    """
    Embed binary data into an image using aggressive LSB steganography.
    Uses 4 bits per channel and resizes image if needed to fit large data.
    Supports JPEG and PNG input images.
    
    Args:
        image_path (str): Path to input image (JPEG or PNG)
        data_path (str): Path to binary data file to hide
        output_path (str): Path for output image with hidden data
    
    Returns:
        bool: True if embedding successful
    """
    
    print(f"Loading image: {image_path}")
    print(f"Loading data: {data_path}")
    
    # Read the binary data to hide
    with open(data_path, 'rb') as f:
        data_bytes = f.read()
    
    print(f"Data size: {len(data_bytes):,} bytes")
    
    # Open and process the JPEG image
    img = Image.open(image_path)
    
    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    total_pixels = width * height
    
    # Calculate capacity using multiple bits per channel (more aggressive embedding)
    bits_per_channel = 4  # Use 4 LSBs per channel instead of just 1
    bits_per_pixel = 3 * bits_per_channel  # R, G, B channels
    max_capacity_bits = total_pixels * bits_per_pixel
    max_capacity_bytes = max_capacity_bits // 8
    
    # If data still doesn't fit, resize the image
    if len(data_bytes) + 100 > max_capacity_bytes:  # +100 for headers
        required_pixels = (len(data_bytes) + 100) * 8 // bits_per_pixel
        new_size = int((required_pixels ** 0.5)) + 1
        
        print(f"Resizing image to fit data: {width}x{height} -> {new_size}x{new_size}")
        
        # Resize image to fit the data
        img = img.resize((new_size, new_size), Image.LANCZOS)
        width, height = img.size
        total_pixels = width * height
        max_capacity_bits = total_pixels * bits_per_pixel
        max_capacity_bytes = max_capacity_bits // 8
    
    # Create the payload with headers and error checking
    data_length = struct.pack('<I', len(data_bytes))  # 4 bytes length
    
    # Calculate SHA-256 hash for data integrity
    data_hash = hashlib.sha256(data_bytes).digest()  # 32 bytes
    
    # Create complete payload
    payload = magic_header + data_length + data_hash + data_bytes + magic_header
    payload_size = len(payload)
    
    # Data should fit now due to resizing and aggressive bit usage
    if payload_size > max_capacity_bytes:
        raise ValueError(f"Data too large even after resizing! Need {payload_size:,} bytes, capacity: {max_capacity_bytes:,} bytes")
    
    # Convert payload to binary string
    binary_data = ''.join(format(byte, '08b') for byte in payload)
    
    # Pad with zeros to fill remaining capacity (helps with extraction)
    while len(binary_data) < max_capacity_bits:
        binary_data += '0'
    
    # Convert image to numpy array for bit manipulation
    img_array = np.array(img)
    
    # Embed the binary data into LSBs
    bit_index = 0
    pixels_modified = 0
    
    for y in range(height):
        for x in range(width):
            pixel = img_array[y, x]
            original_pixel = pixel.copy()
            
            # Modify multiple LSBs of each color channel (R, G, B)
            for channel in range(3):
                for bit_pos in range(bits_per_channel):
                    if bit_index < len(binary_data):
                        # Clear the specific bit and set it to our data bit
                        mask = ~(1 << bit_pos) & 0xFF  # Ensure mask stays within uint8 bounds
                        new_value = (int(pixel[channel]) & mask) | (int(binary_data[bit_index]) << bit_pos)
                        pixel[channel] = np.uint8(new_value)  # Explicitly cast to uint8
                        bit_index += 1
            
            img_array[y, x] = pixel
            
            # Count modified pixels
            if not np.array_equal(original_pixel, pixel):
                pixels_modified += 1
    
    # Convert back to PIL Image and save as JPEG
    result_img = Image.fromarray(img_array, 'RGB')
    
    # Save as PNG to preserve exact pixel values (JPEG is lossy and corrupts LSB data)
    # Change output extension to .png for lossless storage
    if output_path.endswith('.jpg') or output_path.endswith('.jpeg'):
        output_path = output_path.rsplit('.', 1)[0] + '.png'
    elif not output_path.endswith('.png'):
        output_path = output_path + '.png'
    
    result_img.save(output_path, 'PNG')
    
    print(f"Saved: {output_path}")
    
    return True


def extract_data_from_image(image_path, output_path):
    """
    Extract hidden data from an image (JPEG or PNG).
    
    Args:
        image_path (str): Path to image with hidden data
        output_path (str): Path to save extracted data
    
    Returns:
        bool: True if extraction successful
    """
    
    print(f"Extracting data from: {image_path}")
    
    # Open the image
    img = Image.open(image_path)
    
    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    img_array = np.array(img)
    
    # Extract LSBs from all pixels
    binary_data = ""
    
    for y in range(height):
        for x in range(width):
            pixel = img_array[y, x]
            
            # Extract multiple bits from each color channel
            for channel in range(3):
                for bit_pos in range(4):  # Extract 4 bits per channel
                    binary_data += str((pixel[channel] >> bit_pos) & 1)
    
    # Convert binary string back to bytes
    extracted_bytes = bytearray()
    for i in range(0, len(binary_data), 8):
        if i + 7 < len(binary_data):
            byte_str = binary_data[i:i+8]
            extracted_bytes.append(int(byte_str, 2))
    
    # Look for magic header
    magic_length = len(magic_header)
    
    if len(extracted_bytes) < magic_length + 4 + 32 + magic_length:  # header + length + hash + footer
        raise ValueError("Insufficient data extracted from image")
    
    # Check magic header
    found_magic = bytes(extracted_bytes[:magic_length])
    if found_magic != magic_header:
        raise ValueError(f"Magic header not found. Expected {magic_header}, got {found_magic}")
    
    # Extract data length
    length_start = magic_length
    length_end = length_start + 4
    data_length = struct.unpack('<I', extracted_bytes[length_start:length_end])[0]
    
    # Validate data length
    if data_length > len(extracted_bytes) - magic_length - 4 - 32 - magic_length:
        raise ValueError(f"Invalid data length: {data_length:,} bytes")
    
    # Extract stored hash
    hash_start = length_end
    hash_end = hash_start + 32
    stored_hash = bytes(extracted_bytes[hash_start:hash_end])
    
    # Extract the actual hidden data
    data_start = hash_end
    data_end = data_start + data_length
    hidden_data = bytes(extracted_bytes[data_start:data_end])
    
    # Verify hash
    calculated_hash = hashlib.sha256(hidden_data).digest()
    
    if stored_hash != calculated_hash:
        print("Warning: Hash mismatch - data may be corrupted")
    
    # Save the extracted data
    with open(output_path, 'wb') as f:
        f.write(hidden_data)
    
    print(f"Extracted {len(hidden_data):,} bytes to: {output_path}")
    
    return True


def verify_extraction(original_file, extracted_file):
    """
    Compare original and extracted files to verify perfect recovery.
    
    Args:
        original_file (str): Path to original data file
        extracted_file (str): Path to extracted data file
    
    Returns:
        bool: True if files are identical
    """
    
    # Read both files
    with open(original_file, 'rb') as f:
        original_data = f.read()
    
    with open(extracted_file, 'rb') as f:
        extracted_data = f.read()
    
    # Compare files
    if original_data == extracted_data:
        print("Verification: Files are identical")
        return True
    else:
        print("Verification: Files differ")
        
        return False


def main():
    """
    Main function - handles command line arguments and orchestrates the steganography process.
    Usage:
        python steganography.py embed <image_file> <data_file> [output_file]
        python steganography.py extract <stego_image> [output_file]
        python steganography.py verify <original_data> <stego_image>
    """
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Embed: python steganography.py embed <image_file> <data_file> [output_file]")
        print("  Extract: python steganography.py extract <stego_image> [output_file]")
        print("  Verify: python steganography.py verify <original_data> <stego_image>")
        print("")
        print("Examples:")
        print("  python steganography.py embed photo.jpg data.bin")
        print("  python steganography.py embed photo.png secret.bin hidden.png")
        print("  python steganography.py extract hidden.png")
        print("  python steganography.py extract hidden.png extracted.bin")
        print("  python steganography.py verify data.bin hidden.png")
        return False
    
    command = sys.argv[1].lower()
    
    if command == "embed":
        if len(sys.argv) < 4:
            print("Error: embed requires image file and data file")
            print("Usage: python steganography.py embed <image_file> <data_file> [output_file]")
            return False
        
        input_image = sys.argv[2]
        input_data = sys.argv[3]
        
        # Generate output filename if not provided
        if len(sys.argv) >= 5:
            output_image = sys.argv[4]
        else:
            # Auto-generate output filename based on input image
            base_name = os.path.splitext(input_image)[0]
            output_image = f"{base_name}_hidden.png"
        
        # Check if input files exist
        missing_files = []
        for filepath in [input_image, input_data]:
            if not os.path.exists(filepath):
                missing_files.append(filepath)
        
        if missing_files:
            print(f"Missing files: {', '.join(missing_files)}")
            return False
        
        # Check image format
        try:
            with Image.open(input_image) as img:
                pass  # Just checking if it can be opened
        except Exception as e:
            print(f"Invalid image file '{input_image}': {e}")
            return False
        
        try:
            embed_data_in_image(input_image, input_data, output_image)
            print("Embedding completed")
            return True
        except Exception as e:
            print(f"Embedding failed: {e}")
            return False
            
    elif command == "extract":
        if len(sys.argv) < 3:
            print("Error: extract requires image file")
            print("Usage: python steganography.py extract <stego_image> [output_file]")
            return False
        
        stego_image = sys.argv[2]
        
        # Generate output filename if not provided
        if len(sys.argv) >= 4:
            extracted_data = sys.argv[3]
        else:
            extracted_data = "extracted_data.bin"
        
        if not os.path.exists(stego_image):
            print(f"File not found: {stego_image}")
            return False
        
        try:
            extract_data_from_image(stego_image, extracted_data)
            print("Extraction completed")
            return True
        except Exception as e:
            print(f"Extraction failed: {e}")
            return False
    
    elif command == "verify":
        if len(sys.argv) < 4:
            print("Error: verify requires original data file and steganographic image")
            print("Usage: python steganography.py verify <original_data> <stego_image>")
            return False
        
        original_data = sys.argv[2]
        stego_image = sys.argv[3]
        
        # Check if files exist
        missing_files = []
        for filepath in [original_data, stego_image]:
            if not os.path.exists(filepath):
                missing_files.append(filepath)
        
        if missing_files:
            print(f"Missing files: {', '.join(missing_files)}")
            return False
        
        try:
            # Extract data from steganographic image to temporary file
            temp_extracted = "temp_extracted_for_verify.bin"
            extract_data_from_image(stego_image, temp_extracted)
            
            # Compare with original
            success = verify_extraction(original_data, temp_extracted)
            
            # Clean up temporary file
            try:
                os.remove(temp_extracted)
            except:
                pass
            
            if success:
                print("Verification: Data matches perfectly")
            else:
                print("Verification: Data does not match")
            
            return success
            
        except Exception as e:
            print(f"Verification failed: {e}")
            return False
    
    else:
        print(f"Unknown command: {command}")
        print("Usage: python steganography.py [embed|extract|verify] ...")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)