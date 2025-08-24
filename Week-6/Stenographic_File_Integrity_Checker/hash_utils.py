import hashlib
from steg_png import extract_hash_from_image

def generate_file_hash(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()

def verify_file_integrity(stego_img, file_path):
    embedded_hash = extract_hash_from_image(stego_img)
    current_hash = generate_file_hash(file_path)
    return embedded_hash == current_hash
