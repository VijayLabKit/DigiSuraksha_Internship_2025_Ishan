from PIL import Image

def embed_hash_in_image(cover_img_path, stego_img_path, file_hash):
    """
    Embed a SHA256 hash string into an image using LSB steganography.
    Works with any image format (JPEG, JPG, PNG, RGBA PNG, etc.)
    """

    # Open and convert image to RGB to avoid RGBA unpacking issues
    img = Image.open(cover_img_path).convert("RGB")
    pixels = img.load()

    # Convert the hash string into a binary string
    binary_hash = ''.join(format(ord(char), '08b') for char in file_hash)
    hash_length = len(binary_hash)

    width, height = img.size
    capacity = width * height * 3  # 3 channels (R, G, B)

    if hash_length > capacity:
        raise ValueError("Image too small to embed this hash!")

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index >= hash_length:
                break

            r, g, b = pixels[x, y]

            # Modify the R channel LSB
            if data_index < hash_length:
                r = (r & ~1) | int(binary_hash[data_index])
                data_index += 1

            # Modify the G channel LSB
            if data_index < hash_length:
                g = (g & ~1) | int(binary_hash[data_index])
                data_index += 1

            # Modify the B channel LSB
            if data_index < hash_length:
                b = (b & ~1) | int(binary_hash[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

        if data_index >= hash_length:
            break

    # Save the new image
    img.save(stego_img_path, "PNG")
    print(f"✅ Hash successfully embedded into {stego_img_path}")


def extract_hash_from_image(stego_img_path, hash_length=64):
    """
    Extract a SHA256 hash string from a stego image.
    """

    # Open and convert image to RGB to avoid RGBA issues
    img = Image.open(stego_img_path).convert("RGB")
    pixels = img.load()

    width, height = img.size

    binary_hash = ""
    data_index = 0
    required_bits = hash_length * 8  # Each hex char = 8 bits

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]

            if data_index < required_bits:
                binary_hash += str(r & 1)
                data_index += 1

            if data_index < required_bits:
                binary_hash += str(g & 1)
                data_index += 1

            if data_index < required_bits:
                binary_hash += str(b & 1)
                data_index += 1

            if data_index >= required_bits:
                break

        if data_index >= required_bits:
            break

    # Convert binary string back to text
    extracted_hash = ""
    for i in range(0, len(binary_hash), 8):
        byte = binary_hash[i:i+8]
        extracted_hash += chr(int(byte, 2))

    return extracted_hash
