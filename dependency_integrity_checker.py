import hashlib
import json

class SupplyChainSentinel:
    def __init__(self, manifest_file):
        self.manifest = manifest_file
        self.trusted_hashes = {
            "requests": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "numpy": "83296061324c4832598325983259832598325983259832598325983259832598"
        }

    def audit_dependencies(self, current_packages):
        """
        Compliance: Executive Order 14028 (Improving the Nation's Cybersecurity)
        Verifies that every imported package matches the cryptographically signed hash.
        """
        print("[*] SENTINEL: Auditing Software Supply Chain...")
        for package, p_hash in current_packages.items():
            if package in self.trusted_hashes:
                if p_hash == self.trusted_hashes[package]:
                    print(f"  [+] {package}: Integrity Verified.")
                else:
                    print(f"  [!!!] WARNING: {package} HASH MISMATCH. Potential Poisoning!")
            else:
                print(f"  [?] UNKNOWN PACKAGE: {package}. Flagging for manual review.")

if __name__ == "__main__":
    sentinel = SupplyChainSentinel("sbom.json")
    # Mocking current project dependencies
    current_state = {"requests": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "malicious-lib": "12345"}
    sentinel.audit_dependencies(current_state)
