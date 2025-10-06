# stegoldr

A steganography toolkit that allows you to hide binary data inside image files (PNG and JPG). The toolkit provides Python utilities for embedding data into images and C code for extracting the hidden data.

## Installation

1. Clone this repository:
```bash
git clone https://github.com/ctrgrb/stegoldr.git
cd stegoldr
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Python Script - Embedding and Extraction

**Embed data into an image:**
```bash
python stego_utils.py embed <image_file> <data_file> [output_file]
```

**Extract data from an image:**
```bash
python stego_utils.py extract <stego_image> [output_file]
```

**Verify data integrity:**
```bash
python stego_utils.py verify <original_data> <stego_image>
```

### Examples

```bash
# Embed a file into an image
python stego_utils.py embed examples/test.jpg examples/data.bin

# Extract data from a steganographic image
python stego_utils.py extract examples/test_hidden.png extracted_data.bin

# Verify that the extraction matches the original
python stego_utils.py verify examples/data.bin examples/test_hidden.png
```

### C Code Integration

For extracting data in C applications:

1. Include `stb_image.h` in your project (download from [stb repository](https://github.com/nothings/stb))
2. Copy the code from `steganography_single_file.c` into your project
3. Update the following constants:
   - `png_path`: Path to your steganographic image
   - `MAGIC_HEADER`: Should match the header used during embedding (default: "X9K7Q2M8")
4. Call `extract_steganography_data()` to extract data into global variables

The extracted data will be available in:
- `Payload[]`: Array containing the extracted data
- `Payload_size`: Size of the extracted data

## Limitations

- Large data files will visibly alter the host image
- Only works with RGB images (automatically converts other formats)
- Requires lossless image format (PNG) for reliable extraction
- C extraction code is Windows-specific (uses Windows.h for MessageBox)
