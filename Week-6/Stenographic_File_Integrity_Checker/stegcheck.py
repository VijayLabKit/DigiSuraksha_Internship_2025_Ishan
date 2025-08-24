import argparse
from steg_png import embed_hash_in_image, extract_hash_from_image
from hash_utils import generate_file_hash, verify_file_integrity

def main():
    parser = argparse.ArgumentParser(description="Stenographic File Integrity Checker")
    parser.add_argument("command", choices=["hash", "embed", "extract", "verify"])
    parser.add_argument("args", nargs="*")
    args = parser.parse_args()

    if args.command == "hash":
        file_path = args.args[0]
        print(f"SHA256 Hash: {generate_file_hash(file_path)}")

    elif args.command == "embed":
        cover_img, stego_img, file_path = args.args
        file_hash = generate_file_hash(file_path)
        embed_hash_in_image(cover_img, stego_img, file_hash)
        print(f"Hash embedded into {stego_img}")

    elif args.command == "extract":
        stego_img = args.args[0]
        print(f"Extracted hash: {extract_hash_from_image(stego_img)}")

    elif args.command == "verify":
        stego_img = args.args[0]
        file_path = args.args[1]
        if verify_file_integrity(stego_img, file_path):
            print("✅ File integrity verified. No tampering detected.")
        else:
            print("❌ File has been tampered with!")

if __name__ == "__main__":
    main()
