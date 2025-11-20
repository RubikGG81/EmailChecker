from pathlib import Path
from dataclasses import dataclass, field
import argparse
from typing import List


@dataclass
class CheckResult:
    # Risultato di un singolo controllo
    check_name: str
    score: int
    max_score: int
    reasons: List[str] = field(default_factory=list)
    
    def add_reason(self, reason: str, points: int = 0):
        # Aggiunge una motivazione e dei punti al risultato del controllo
        self.reasons.append(reason)
        self.score += points


class EmailPhishingDetector:
    # Analizzatore di email per rilevamento phishing
    
    # Estensioni da considerare come pericolose
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.zip', '.rar', '.dll', '.reg', '.lnk'
    }
    
    # Parole aa considerare come sospette
    SUSPICIOUS_KEYWORDS = [
        'urgente', 'immediato', 'verifica',
        'sospeso', 'account', 'password', 'conferma',
        'clicca qui', 'aggiorna',
        'sicurezza', 'allerta', 'avviso',
        'scadenza', 'vincitore', 'premio',
        'banca', 'tasse', 'rimborso',
        'fattura', 'pagamento', 'consegna',
        'azione richiesta', 'non autorizzato', 'accesso'
    ]
    
    def __init__(self, eml_path: str):
        self.eml_path = Path(eml_path)
        self.message = None
        self.results: List[CheckResult] = []
        self.total_score = 0
        self.max_total_score = 0
        
    def load_email(self) -> bool:
        # Carica il file EML
        try:
            with open(self.eml_path, 'rb') as f:
                self.message = BytesParser(policy=policy.default).parse(f)
            return True
        except Exception as e:
            print(f"Errore nel caricamento del file: {e}")
            return False
    
    def _extract_email(self, header: str) -> str:
        # Estrae l'indirizzo email dall'header
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header)
        return match.group(0) if match else ''
    
    def _get_body_text(self) -> str:
        # Estrae il testo dal body dell'email
        body = ""
        if self.message.is_multipart():
            for part in self.message.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif part.get_content_type() == "text/html":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = self.message.get_payload(decode=True).decode('utf-8', errors='ignore')
        return body
    
    def _extract_links(self, text: str) -> List[str]:
        # Estrae tutti i link dal testo o almeno ci prova
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def _is_ip_address(self, hostname: str) -> bool:
        # Verifica se l'hostname è un indirizzo IP raw
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
    
    def check_spf(self) -> CheckResult:
        # Controlla la validità SPF
        result = CheckResult("SPF Validation", 0, 30)
        received_spf = self.message.get('Received-SPF', '').lower()
        auth_results = self.message.get('Authentication-Results', '').lower()
        
        if not received_spf and 'spf=' not in auth_results:
            result.add_reason("Record SPF non trovato negli header", 10)
        elif 'fail' in received_spf or 'spf=fail' in auth_results:
            result.add_reason("SPF FAIL - Il mittente non è autorizzato", 30)
        elif 'softfail' in received_spf or 'spf=softfail' in auth_results:
            result.add_reason("SPF SOFTFAIL - Mittente potenzialmente non autorizzato", 20)
        elif 'neutral' in received_spf or 'spf=neutral' in auth_results:
            result.add_reason("SPF NEUTRAL - Nessuna politica definita", 15)
        elif 'pass' in received_spf or 'spf=pass' in auth_results:
            result.add_reason("SPF PASS - Mittente autorizzato", 0)
        else:
            result.add_reason("SPF non verificabile, è consigliato un controllo manuale con altro tool dedicato", 5)
        return result

    def check_dkim(self) -> CheckResult:
        # Controlla la firma DKIM
        result = CheckResult("DKIM Signature", 0, 25)
        auth_results = self.message.get('Authentication-Results', '').lower()
        dkim_signature = self.message.get('DKIM-Signature', '')
        
        if not dkim_signature and 'dkim=' not in auth_results:
            result.add_reason("Firma DKIM assente", 15)
        elif 'dkim=fail' in auth_results:
            result.add_reason("DKIM FAIL - Firma non valida", 25)
        elif 'dkim=pass' in auth_results:
            result.add_reason("DKIM PASS - Firma valida", 0)
        else:
            result.add_reason("DKIM presente ma non verificabile", 10)
        
        return result

    def check_dmarc(self) -> CheckResult:
        # Controlla la policy DMARC
        result = CheckResult("DMARC Policy", 0, 25)
        
        auth_results = self.message.get('Authentication-Results', '').lower()
        
        if 'dmarc=' not in auth_results:
            result.add_reason("Risultato DMARC non trovato", 15)
        elif 'dmarc=fail' in auth_results:
            result.add_reason("DMARC FAIL - Policy non rispettata", 25)
        elif 'dmarc=pass' in auth_results:
            result.add_reason("DMARC PASS - Policy rispettata", 0)
        else:
            result.add_reason("DMARC non verificabile", 10)
        
        return result

    
    def analyze(self):
        # Esegue tutti i controlli uno dopo l'altro TODO
        
              
        if not self.load_email():
            return
        
        print("\n" + "="*70)
        print("ANALISI EMAIL PER RILEVAMENTO PHISHING")
        print("="*70)
        print(f"\n File: {self.eml_path.name}")
        print(f" Subject: {self.message.get('Subject', 'N/A')}")
        print(f" From: {self.message.get('From', 'N/A')}")
        print(f" Date: {self.message.get('Date', 'N/A')}\n")
        
        # Esegue i controlli TODO
        self.results.append(self.check_spf())
        self.results.append(self.check_dkim())
        self.results.append(self.check_dmarc())
        
        # Mostra risultati TODO


    
    def _print_results(self):
        # Stampa i risultati dell'analisi
        print("="*70)
        print("RISULTATI DETTAGLIATI")
        print("="*70 + "\n")
        
        for result in self.results:
            print(f"🔸 {result.check_name}")
            print(f"   Score: {result.score}/{result.max_score}")
            for reason in result.reasons:
                print(f"   {reason}")
            print()
        
        # Aggiungere Calcolo Score finale  TODO 


def main():
    parser = argparse.ArgumentParser(
        description='Analizza file .eml per rilevare possibili tentativi di phishing'
    )
    parser.add_argument(
        'eml_file',
        help='Path del file .eml da analizzare'
    )
    
    args = parser.parse_args()
    
    detector = EmailPhishingDetector(args.eml_file)
    detector.analyze()


if __name__ == "__main__":
    main()