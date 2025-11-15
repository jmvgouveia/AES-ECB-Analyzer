# Protótipo principal

#!/usr/bin/env python3
"""
Protótipo de Análise de Mensagem Cifrada AES-ECB
Desenvolvido para fins académicos - Mestrado em Criptografia

"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from typing import List, Tuple, Optional
import time

class AESECBAnalyzer:
    """Classe para análise e ataque a mensagens cifradas com AES-ECB"""
    
    def __init__(self, ciphertext_b64: str, known_plaintext: str):
        """
        Inicializa o analisador
        
        Args:
            ciphertext_b64: Mensagem cifrada em Base64
            known_plaintext: Texto conhecido do início da mensagem
        """
        self.ciphertext_b64 = ciphertext_b64
        self.ciphertext = base64.b64decode(ciphertext_b64)
        self.known_plaintext = known_plaintext
        self.block_size = 16  # AES usa blocos de 16 bytes
        
    def analyze_ecb_patterns(self) -> dict:
        """
        Analisa padrões no ciphertext que são característicos do modo ECB
        
        Returns:
            Dicionário com análise de blocos e padrões repetidos
        """
        num_blocks = len(self.ciphertext) // self.block_size
        blocks = []
        block_map = {}
        
        print(f"\n{'='*60}")
        print("ANÁLISE DE PADRÕES ECB")
        print(f"{'='*60}")
        print(f"Tamanho do ciphertext: {len(self.ciphertext)} bytes")
        print(f"Número de blocos: {num_blocks}")
        print(f"Tamanho do bloco: {self.block_size} bytes (128 bits)")
        
        for i in range(num_blocks):
            block = self.ciphertext[i * self.block_size:(i + 1) * self.block_size]
            block_hex = block.hex()
            blocks.append({
                'index': i,
                'hex': block_hex,
                'bytes': block
            })
            
            if block_hex not in block_map:
                block_map[block_hex] = []
            block_map[block_hex].append(i)
        
        # Identificar blocos repetidos
        repeated_blocks = {k: v for k, v in block_map.items() if len(v) > 1}
        
        print(f"\nBlocos repetidos encontrados: {len(repeated_blocks)}")
        if repeated_blocks:
            print("   VULNERABILIDADE ECB CONFIRMADA!")
            print("   Blocos idênticos de plaintext produzem ciphertext idêntico\n")
            for block_hex, indices in repeated_blocks.items():
                print(f"   Bloco {block_hex[:16]}... aparece nas posições: {indices}")
        else:
            print("   Nenhum bloco repetido detectado")
        
        return {
            'num_blocks': num_blocks,
            'blocks': blocks,
            'repeated_blocks': repeated_blocks
        }
    
    def prepare_key(self, key_string: str, key_size: int) -> bytes:
        """
        Prepara uma chave do tamanho correto a partir de uma string
        
        Args:
            key_string: String da chave
            key_size: Tamanho desejado em bytes (16, 24 ou 32)
            
        Returns:
            Chave em bytes do tamanho correto
        """
        key_bytes = key_string.encode('utf-8')
        
        # Se a chave for menor, repete até o tamanho desejado
        if len(key_bytes) < key_size:
            key = (key_bytes * (key_size // len(key_bytes) + 1))[:key_size]
        else:
            key = key_bytes[:key_size]
        
        return key
    
    def try_decrypt(self, key: bytes) -> Optional[str]:
        """
        Tenta decifrar o ciphertext com uma chave específica
        
        Args:
            key: Chave em bytes
            
        Returns:
            Plaintext decifrado ou None se falhar
        """
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(self.ciphertext)
            
            # Tentar remover padding PKCS7
            try:
                decrypted = unpad(decrypted, self.block_size)
            except:
                pass  # Se não tiver padding válido, continua sem remover
            
            # Tentar decodificar como UTF-8
            plaintext = decrypted.decode('utf-8', errors='ignore')
            
            # Verificar se contém o plaintext conhecido
            if self.known_plaintext in plaintext:
                return plaintext
            
        except Exception:
            pass
        
        return None
    
    def brute_force_attack(self, wordlist: List[str], verbose: bool = True) -> List[Tuple[str, str, int]]:
        """
        Ataque de força bruta com dicionário de palavras
        
        Args:
            wordlist: Lista de possíveis chaves
            verbose: Se True, mostra progresso
            
        Returns:
            Lista de tuplas (chave, plaintext, tamanho_bits)
        """
        results = []
        key_sizes = [16, 24, 32, 64]  # 128, 192, 256, 512 bits
        
        print(f"\n{'='*60}")
        print("ATAQUE DE FORÇA BRUTA DIRECIONADA")
        print(f"{'='*60}")
        print(f"Testando {len(wordlist)} chaves candidatas")
        print(f"Tamanhos de chave: 128, 192, 256 bits")
        print(f"Plaintext conhecido: '{self.known_plaintext}'\n")
        
        start_time = time.time()
        tested = 0
        
        for key_string in wordlist:
            for key_size in key_sizes:
                tested += 1
                
                if verbose and tested % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"Progresso: {tested}/{len(wordlist)*3} tentativas "
                          f"({rate:.1f} chaves/seg)", end='\r')
                
                key = self.prepare_key(key_string, key_size)
                plaintext = self.try_decrypt(key)
                
                if plaintext:
                    results.append((key_string, plaintext, key_size * 8))
                    if verbose:
                        print(f"\n\n ***SUCESSO!*** Chave encontrada: '{key_string}'")
                        print(f"   Tamanho da chave: {key_size * 8} bits")
        
        elapsed = time.time() - start_time
        print(f"\n\n  Tempo total: {elapsed:.2f} segundos")
        print(f" Total de tentativas: {tested}")
        
        return results
    
    def test_custom_key(self, key_string: str) -> List[Tuple[str, str, int]]:
        """
        Testa uma chave personalizada específica
        
        Args:
            key_string: String da chave a testar
            
        Returns:
            Lista de resultados bem-sucedidos
        """
        results = []
        key_sizes = [16, 24, 32]
        
        print(f"\n{'='*60}")
        print(f"TESTANDO CHAVE PERSONALIZADA: '{key_string}'")
        print(f"{'='*60}\n")
        
        for key_size in key_sizes:
            key = self.prepare_key(key_string, key_size)
            plaintext = self.try_decrypt(key)
            
            if plaintext:
                print(f"Sucesso com chave de {key_size * 8} bits!")
                results.append((key_string, plaintext, key_size * 8))
            else:
                print(f"Falhou com chave de {key_size * 8} bits")
        
        return results
    
    def generate_wordlist(self) -> List[str]:
        """
        Gera lista de palavras-chave comuns para o contexto
        
        Returns:
            Lista de possíveis chaves
        """
        # Palavras relacionadas ao contexto criminal/tráfico
        crime_words = ['droga',
                       'cocaina',
                       'trafego',
                       'carregamento', 
                       'operacao',
                       'entrega',
                       'descarga',
                       'mercadoria']

        # Senhas comuns
        common_passwords = ['password',
                            '123',
                            '12345678',
                            'qwerty',
                            'admin',
                            'senha',
                            'chave',
                            '1234567890123456',
                            'teste',
                            ]
        
        # Locais em Portugal
        locations = ['porto',
                     'lisboa',
                     'faro',
                     'Vale do Tejo',
                     'Viana do Castelo',
                     'coimbra',
                     'braga',
                     'setubal',
                     'aveiro',
                     'madeira',
                     'acores']
        
        
        # Combinações e variações
        wordlist = []
        wordlist.extend(crime_words)
        wordlist.extend(common_passwords)
        wordlist.extend(locations)
        
        # Adicionar variações com números
        for word in crime_words + locations:
            wordlist.extend([f"{word}123", f"{word}2024", f"{word}2025"])

        # Adicionar palavras com caracteres especiais
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*']
        for word in crime_words + locations:
            for char in special_chars:
                wordlist.append(f"{word}{char}")

        # Adicionar palavras em maiúsculas
        wordlist.extend([w.upper() for w in crime_words[:5]])
        wordlist.extend([w.upper() for w in locations[:5]])
        wordlist.extend([w.capitalize() for w in common_passwords[:5]])
        
        return wordlist


def print_result(key: str, plaintext: str, key_size: int):
    """Imprime resultado formatado"""
    print(f"\n{'='*60}")
    print("MENSAGEM DECIFRADA COM SUCESSO!")
    print(f"{'='*60}")
    print(f"Chave utilizada: {key}")
    print(f"Tamanho da chave: {key_size} bits")
    print(f"\n{'─'*60}")
    print("CONTEÚDO DA MENSAGEM:")
    print(f"{'─'*60}")
    print(plaintext)
    print(f"{'─'*60}\n")


def main():
    """Função principal do protótipo"""
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║   PROTÓTIPO: ANÁLISE DE MENSAGEM CIFRADA AES-ECB              ║
║   MCSR - Criptografia para Cibersegurança e Resiliência       ║
║   ISCTE-IUL, 2025                                             ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    # # Dados do problema

    ciphertext_b64 = input("Introduza o ciphertext em Base64 (ou pressione Enter para usar o do enunciado): ").strip()
    if not ciphertext_b64:
        ciphertext_b64 = ("7BtgbSJOkkVA5+9UA8/7W9KXn3qEp7yO9tqnlNwiz6+XRW3ywKzEWVSWAdyoh822"
                           "puL2lSb/JQDyoYoYbXG8BpGl9S4U5MQo8LXJXK8hrQjHPYhvwtFXYv3KSLdq/LxX")
        
    known_plaintext = input("\nIntroduza o plaintext conhecido (ou pressione Enter para usar o do enunciado): ").strip()
    if not known_plaintext:
        known_plaintext = "Local de descarga:"

    # Inicializar analisador
    analyzer = AESECBAnalyzer(ciphertext_b64, known_plaintext)
    
    # 1. Análise de padrões ECB
    analyzer.analyze_ecb_patterns()
    
    # 2. Gerar wordlist

    wordlist = analyzer.generate_wordlist()
    
    # 3. Executar ataque
    results = analyzer.brute_force_attack(wordlist)
    
    # 4. Mostrar resultados
    if results:
        print(f"\n{'='*60}")
        print(f"TOTAL DE CHAVES VÁLIDAS ENCONTRADAS: {len(results)}")
        print(f"{'='*60}\n")
        
        for key, plaintext, key_size in results:
            print_result(key, plaintext, key_size)
    else:
        print("\n *** Nenhuma chave válida encontrada no dicionário. ***")
        
        
        # Permitir teste de chave personalizada
        print(f"\n{'─'*60}")


        custom = input("Deseja ver as chaves testadas? (s/n): ")
        if custom.lower() == 's':
            
            print(f"\n--- IMPRIMINDO {len(wordlist)} CHAVES TESTADAS ---\n")
            print("\n".join(wordlist))
            print(f"{'─'*60}\n")
          

        
        custom = input("Deseja testar uma chave personalizada? (s/n): ")
        if custom.lower() == 's':
            key_input = input("Digite a chave: ")
            results = analyzer.test_custom_key(key_input)
            if results:
                for key, plaintext, key_size in results:
                    print_result(key, plaintext, key_size)


if __name__ == "__main__":
    main()