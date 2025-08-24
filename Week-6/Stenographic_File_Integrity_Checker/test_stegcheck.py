import os
import unittest
from steg_png import embed_hash_in_image, extract_hash_from_image
from hash_utils import generate_file_hash, verify_file_integrity
from PIL import Image

class TestStegCheck(unittest.TestCase):

    def setUp(self):
        """Setup temporary test files before each test."""
        self.test_dir = os.path.abspath("test_temp")
        os.makedirs(self.test_dir, exist_ok=True)

        self.cover_img = os.path.join(self.test_dir, "cover.png")
        self.stego_img = os.path.join(self.test_dir, "stego.png")
        self.file_path = os.path.join(self.test_dir, "sample.txt")

        # Create a sample text file
        with open(self.file_path, "w") as f:
            f.write("Hello World")

        # Create a blank cover image
        Image.new("RGB", (200, 200), "white").save(self.cover_img)

    def tearDown(self):
        """Clean up all generated files after tests."""
        for file in [self.cover_img, self.stego_img, self.file_path]:
            if os.path.exists(file):
                os.remove(file)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_hash_generation(self):
        """Test that SHA256 hash is generated correctly."""
        h = generate_file_hash(self.file_path)
        self.assertEqual(len(h), 64)  # SHA256 hash must be 64 hex characters

    def test_embedding_and_extraction(self):
        """Test embedding a hash and extracting it back from the image."""
        h = generate_file_hash(self.file_path)
        embed_hash_in_image(self.cover_img, self.stego_img, h)
        extracted = extract_hash_from_image(self.stego_img)
        self.assertEqual(extracted, h)

    def test_file_integrity(self):
        """Test that integrity verification works correctly."""
        h = generate_file_hash(self.file_path)
        embed_hash_in_image(self.cover_img, self.stego_img, h)

        # Case 1: File not tampered
        self.assertTrue(verify_file_integrity(self.stego_img, self.file_path))

        # Case 2: File tampered
        with open(self.file_path, "w") as f:
            f.write("Tampered Data")
        self.assertFalse(verify_file_integrity(self.stego_img, self.file_path))


if __name__ == "__main__":
    unittest.main()
