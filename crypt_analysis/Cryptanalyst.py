import re
from typing import Callable, Optional, Tuple, List, Dict, Any
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import time


class Cryptanalyst:
    """
    Comprehensive cryptanalysis toolkit for S-DES and S-AES cipher implementations.
    Supports multiple modes of operation and attack vectors.
    """

    def __init__(self, decrypt_fn: Callable[[bytes, int, Optional[int]], bytes], block_size: int = 8):
        """
        Initialize the cryptanalyst with target decryption function.

        Args:
            decrypt_fn: Function that takes (ciphertext, key, iv) and returns plaintext bytes
            block_size: Block size in bits (8 for S-DES, 16 for S-AES)
        """
        self.decrypt = decrypt_fn
        self.block_size = block_size
        self.byte_block_size = block_size // 8

        self.english_freq = {
            ' ': 0.15, 'e': 0.12, 't': 0.09, 'a': 0.08,
            'o': 0.07, 'i': 0.06, 'n': 0.06, 's': 0.06
        }

    def brute_force(self, ciphertext: bytes, known_plaintexts: List[bytes], iv: int = 0, max_workers: int = 4) -> Optional[int]:
        """
        Parallel brute force attack that checks multiple plaintext candidates per key.
        
        Args:
            ciphertext: Encrypted data
            known_plaintexts: List of possible plaintext snippets to look for
            iv: Initialization vector
            max_workers: Number of threads to use
            
        Returns:
            Found key or None if no match found
        """
        def test_key(key: int) -> Optional[int]:
            try:
                if iv is not None : decrypted = self.decrypt(ciphertext, key, iv).lower()
                else : decrypted = self.decrypt(ciphertext, key).lower()     
                for plaintext in known_plaintexts:
                    if plaintext in decrypted:
                        return key
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create futures for all keys
            futures = {executor.submit(test_key, key): key for key in range(0x10000)}
            
            # Process results as they complete
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    # Shutdown immediately if we find a match
                    executor.shutdown(wait=False)
                    return result
        
        return None

    def frequency_analysis(self, ciphertext: bytes, iv: int = None, top_n: int = 5) -> List[Tuple[int, float]]:
        """
        Statistical frequency analysis attack for text.
        """
        results: List[Tuple[int, float]] = []

        for key in range(0x10000):
            try:
                if iv is not None : decrypted = self.decrypt(ciphertext, key, iv).lower()
                else : decrypted = self.decrypt(ciphertext, key).lower()
                freq = Counter(decrypted)
                score = sum(freq.get(c, 0) * self.english_freq.get(c, 0) for c in self.english_freq)
                normalized_score = score / len(decrypted) if decrypted else 0
                results.append((f"0x{key:04x}", normalized_score,decrypted))
            except Exception as e:
                continue

        return sorted(results, key=lambda x: -x[1])[:top_n]

    def optimized_attack(self, ciphertext: bytes, iv: int = None):
        """
        Smart attack that automatically selects best strategy.
        """
        print("\nAttempting frequency analysis...\n")
        candidates = self.frequency_analysis(ciphertext, iv)
        if candidates and candidates[0][1] > 0.5:
            return candidates[0][0]
        else:
            print("(note frequency analysis has levels of accuracy you must read decrypted text and determin for your self if it is correct)\n")
            for candidate in candidates: 
                print(f"Key: {candidate[0]} \npercision: {candidate[1]} \ndecryption: {candidate[2]} \n---------------------------")

        # Fallback to brute force
        common_plaintexts = ['Hello', 'Hi' ,'Secret', 'Data', 'Message', 'The', 'This is', 'File']

        print(f"\nstarting brute force for common text\n(estimated time: {self.estimate_attack_time(ciphertext)})\n")
        key = self.brute_force(ciphertext, common_plaintexts, iv)
        if key is not None:
            return key

        # Fallback to user input
        key = self.interactive_brute_force(ciphertext , iv)
        if key is not None:
            return key

        return None
    

    def interactive_brute_force(self, ciphertext: bytes, iv: int = None) :
        while True:
            print("\nBrute-force failed. Enter known plaintexts to try (comma separated):")
            print("Example: Hello,Secret,My Data 123")
            user_input = input("> ").strip()
            
            if not user_input:
                break
                
            # Process user input
            user_plaintexts = [pt.strip() for pt in user_input.split(',') if pt.strip()]
            
            if not user_plaintexts:
                print("No valid plaintexts entered. Try again.")
                continue
                
            print(f"\nTrying {len(user_plaintexts)} plaintexts in single brute-force run...")
            key = self.brute_force(ciphertext, user_plaintexts, iv)
            
            if key is not None:
                return key
            else:
                print("\nNo key found with these plaintexts.")
    


    def benchmark_decrypt(self, ciphertext: bytes, iv: int = 0, samples: int = 100) -> float:
        """
        Benchmark decryption speed for performance estimation.
        """
        times: List[float] = []
        for _ in range(samples):
            start = time.time()
            try:
                self.decrypt(ciphertext, 0x0000, iv)
            except Exception:
                pass
            times.append(time.time() - start)

        return (sum(times) / len(times)) * 1000 if times else float('inf')

    def estimate_attack_time(self, ciphertext: bytes) -> str:
        """
        Estimate brute force attack time.
        """
        avg_time = self.benchmark_decrypt(ciphertext)
        total_ops = 0x10000
        total_time = (avg_time * total_ops) / 1000

        if total_time < 60:
            return f"~{total_time:.1f} seconds"
        elif total_time < 3600:
            return f"~{total_time / 60:.1f} minutes"
        else:
            return f"~{total_time / 3600:.1f} hours"