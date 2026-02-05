from flash512.engine import Flash512Vanguard
import time

def run_security_audit():
    print("--- 🛡️ START OF THE FLASH512-VANGUARD AUDIT ---")
    
    user_secret = "MyFLASH512-VANGUARDTopSecret123!"
    payload = "This is a highly confidential diplomatic message."

    # TEST 1 : Basic operation
    print("\n[Test 1] Encryption...")
    token = Flash512Vanguard.protect(payload, user_secret)
    print(f"Result (Token): {token[:50]}...")

    # TEST 2 : Decryption
    print("[Test 2] Decryption...")
    decrypted = Flash512Vanguard.open(token, user_secret)
    if decrypted == payload:
        print("✅ SUCCESS: The original message has been found.")

    # TEST 3 : Uniqueness (The 'Flash' effect)
    print("\n[Test 3] Uniqueness verification (Test nonce)...")
    token2 = Flash512Vanguard.protect(payload, user_secret)
    if token != token2:
        print("✅ SUCCESS: Two identical messages produce two different tokens.")

    # TEST 4 : Resistance to attack (Integrity)
    print("\n[Test 4] Simulation of a data attack...")
    corrupted_token = token[:-5] + "ABCDE" # The final signature is modified.
    try:
        Flash512Vanguard.open(corrupted_token, user_secret)
    except PermissionError:
        print("✅ SUCCESS: The attack was detected (Invalid signature).")

if __name__ == "__main__":
    start = time.time()
    run_security_audit()
    print(f"\nAudit completed in {time.time() - start:.4f} seconds.")
