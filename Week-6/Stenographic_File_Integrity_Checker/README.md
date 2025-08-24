# Stenographic File Integrity Checker

**Intern:** Ishan Chowdhury  
**Intern ID:** 159  
**Team:** SkullFaced  

---

## **Overview**
A Python-based tool that hides cryptographic hashes inside cover images using **LSB steganography** to verify file integrity.

---

## **Usage**
```bash
# Install dependencies
pip install pillow

# Generate file hash
python stegcheck.py hash sample.txt

# Embed hash into cover image
python stegcheck.py embed cover.png stego.png sample.txt

# Extract hash
python stegcheck.py extract stego.png

# Verify file integrity
python stegcheck.py verify stego.png sample.txt

# Run unit tests
pytest test_stegcheck.py
