from pathlib import Path
from dataclasses import dataclass, field
import argparse
from typing import List
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import os


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
    
    # Come rifinitura creare func x aggiungere/rimuovere elementi TODO 
    # dal set e della lista e creare un menu guidato di selezione rapida di queste func ed altre opzioni utili TODO
    
    
    # Estensioni da considerare come pericolose
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.zip', '.rar', '.iso', '.msi', '.dll', '.hta', '.reg',
        '.ps1', '.psm1', '.lnk', '.docm', '.xlsm', '.pptm'
    }

    
    # Parole aa considerare come sospette in eng e ita
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'urgente', 'immediate', 'immediato', 'verify', 'verifica',
        'suspend', 'sospeso', 'account', 'password', 'confirm', 'conferma',
        'click here', 'clicca qui', 'update', 'aggiorna', 'security', 'check', 'controlla', 'controllo',
        'sicurezza', 'alert', 'allerta', 'warning', 'avviso', 'expire',
        'scadenza', 'winner', 'vincitore', 'prize', 'premio', 'bank',
        'banca', 'tax', 'tasse', 'refund', 'rimborso', 'invoice', 'change', 'cambiare', 'phishing',
        'fattura', 'payment', 'pagamento', 'deliver', 'consegna', 'utente', 'username',
        'action required', 'azione richiesta', 'unauthorized', 'non autorizzato'
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
            print(f"❌❌ Errore nel caricamento del file ❌❌: {e}")
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
    
    def _extract_domain_from_email(self, email_str: str) -> str:
        # Estrae il dominio da un indirizzo email o da una stringa che contiene un dominio
        if not email_str:
            return ''
        # Prima prova a estrarre un'email completa
        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_str)
        if email_match:
            return email_match.group(1).lower()
        # Se non c'è un'email, prova a estrarre un dominio diretto
        domain_match = re.search(r'([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', email_str.lower())
        if domain_match:
            return domain_match.group(0).lower()
        return ''

    def check_spf(self) -> CheckResult:
        # Controlla la validità SPF"""
        result = CheckResult("SPF Validation", 0, 30)
        
        received_spf = self.message.get('Received-SPF', '')
        received_spf_lower = received_spf.lower()
        auth_results = self.message.get('Authentication-Results', '')
        auth_results_lower = auth_results.lower()
        
        if not received_spf and 'spf=' not in auth_results_lower:
            result.add_reason("⚠️   Record SPF non trovato negli header", 25)
        elif 'none' in received_spf_lower or 'spf=none' in auth_results_lower:
            result.add_reason("🚨   SPF NONE - Il controllo non è implementato", 25)
        elif 'fail' in received_spf_lower or 'spf=fail' in auth_results_lower:
            result.add_reason("🚨   SPF FAIL - Il mittente non è autorizzato", 30)
        elif 'softfail' in received_spf_lower or 'spf=softfail' in auth_results_lower:
            result.add_reason("⚠️   SPF SOFTFAIL - Mittente potenzialmente non autorizzato", 20)
        elif 'neutral' in received_spf_lower or 'spf=neutral' in auth_results_lower:
            result.add_reason("⚠️   SPF NEUTRAL - Nessuna politica definita", 15)
        elif 'pass' in received_spf_lower or 'spf=pass' in auth_results_lower:
            result.add_reason("✓   SPF PASS - Mittente autorizzato", 0)

            # Controllo aggiuntivo: verifica coerenza domini quando SPF=pass
            spf_domain = ''
            mail_from_domain = ''
            from_domain = ''
            
            # Estrai dominio che ha superato l'SPF
            # Da Received-SPF: "domain of xxx" o simile
            spf_domain_match = re.search(r'domain\s+of\s+([\w\.-]+\.\w+)', received_spf, re.IGNORECASE)
            if spf_domain_match:
                spf_domain = spf_domain_match.group(1).lower()
            
            # Estrai MAIL FROM (smtp.mailfrom) da Authentication-Results
            mail_from_match = re.search(r'smtp\.mailfrom=([\w\.-]+\.\w+)', auth_results, re.IGNORECASE)
            if mail_from_match:
                mail_from_domain = mail_from_match.group(1).lower()
            else:
                # Testo Return-Path se disponibile
                return_path = self.message.get('Return-Path', '')
                if return_path:
                    mail_from_domain = self._extract_domain_from_email(return_path)
            
            # Estrai dominio dal From header (mittente visualizzato))
            from_header = self.message.get('From', '')
            if from_header:
                from_domain = self._extract_domain_from_email(from_header)
            
            # Verifica coerenza dei domini
            domains_found = []
            if spf_domain:
                domains_found.append(('SPF', spf_domain))
            if mail_from_domain:
                domains_found.append(('MAIL FROM', mail_from_domain))
            if from_domain:
                domains_found.append(('From', from_domain))
            
            if len(domains_found) >= 2:
                # Crea un set dei domini unici
                unique_domains = set(d[1] for d in domains_found)
                if len(unique_domains) == 2:
                    # 2 domini non congruenti - punteggio negativo
                    domain_info = ', '.join([f"{name}: {domain}" for name, domain in domains_found])
                    result.add_reason(
                        f"🚨   SPF PASS ma 2 domini non congruenti - {domain_info}", 25)
                elif len(unique_domains) > 2:
                    # 3 domini tutti diversi - punteggio negativo maggiore
                    domain_info = ', '.join([f"{name}: {domain}" for name, domain in domains_found])
                    result.add_reason(
                        f"🚨   SPF PASS ma diversi domini non congruenti - {domain_info}", 30)
                else:
                    result.add_reason("✓   Domini congruenti tra SPF, MAIL FROM e From", 0)
        else:
            result.add_reason("⚠️   SPF non verificabile,è consigliato un controllo manuale con altro tool dedicato", 23)
        
        return result


    def check_dkim(self) -> CheckResult:
        # Controlla la firma DKIM
        result = CheckResult("DKIM Signature", 0, 25)
        
        auth_results = self.message.get('Authentication-Results', '').lower()
        dkim_signature = self.message.get('DKIM-Signature', '')
        
        if not dkim_signature and 'dkim=' not in auth_results:
            result.add_reason("⚠️   Firma DKIM assente", 15)
        elif 'dkim=fail' in auth_results:
            result.add_reason("🚨   DKIM FAIL - Firma non valida", 25)
        elif 'dkim=pass' in auth_results:
            result.add_reason("✓   DKIM PASS - Firma valida", 0)
        elif 'dkim=none' in auth_results:
            result.add_reason("⚠️   Firma DKIM assente", 13)
        else:
            result.add_reason("⚠️   DKIM non verificabile", 13)
        
        return result


    def check_dmarc(self) -> CheckResult:
        # Controlla la policy DMARC
        result = CheckResult("DMARC Policy", 0, 25)
        
        auth_results = self.message.get('Authentication-Results', '').lower()
        
        if 'dmarc=' not in auth_results:
            result.add_reason("⚠️   Risultato DMARC non trovato", 15)
        elif 'dmarc=fail' in auth_results:
            result.add_reason("🚨   DMARC FAIL - Policy non rispettata", 25)
        elif 'dmarc=pass' in auth_results:
            result.add_reason("✓   DMARC PASS - Policy rispettata", 0)
        elif 'dmarc=none' in auth_results:
            result.add_reason("⚠️   Risultato DMARC non trovato", 15)
        else:
            result.add_reason("⚠️   DMARC non verificabile", 13)
        
        return result


    def check_reply_to_mismatch(self) -> CheckResult:
        # Controlla un eventuale mismatch tra From e Reply-To
        result = CheckResult("Reply-To Mismatch", 0, 20)
        
        from_header = self.message.get('From', '')
        reply_to = self.message.get('Reply-To', '')
        
        if not reply_to:
            result.add_reason("ℹ️  Reply-To non presente (normale)", 0)
            return result
        
        # Estrai email da From e Reply-To
        from_email = self._extract_email(from_header)
        reply_email = self._extract_email(reply_to)
        
        if from_email and reply_email:
            from_domain = from_email.split('@')[-1].lower()
            reply_domain = reply_email.split('@')[-1].lower()
            
            if from_domain != reply_domain:
                result.add_reason(
                    f"🚨  MISMATCH Reply-To: From={from_domain}, Reply-To={reply_domain}",
                    20
                )
            else:
                result.add_reason("✓ Reply-To corrisponde al mittente", 0)
        
        return result


    def check_suspicious_content(self) -> CheckResult:
        #Tenta una sorta di analisi euristica del contenuto valutando le  parole sospette
        result = CheckResult("Suspicious Content", 0, 40)
        
        subject = self.message.get('Subject', '').lower()
        body_text = self._get_body_text().lower()
        full_text = f"{subject} {body_text}"
        
        found_keywords = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in full_text:
                found_keywords.append(keyword)
        
        if len(found_keywords) >= 5:
            result.add_reason(
                f"🚨  {len(found_keywords)} parole sospette trovate, un pò troppe (phishing probabile)",
                30
            )
        elif len(found_keywords) >= 3:
            result.add_reason(
                f"⚠️  {len(found_keywords)} parole sospette trovate: {', '.join(found_keywords[:5])}",
                20
            )
        elif len(found_keywords) >= 1:
            result.add_reason(
                f"⚠️  Alcune parole sospette: {', '.join(found_keywords)}",
                10
            )
        else:
            result.add_reason("✓ Nessuna parola particolarmente sospetta", 0)
        
        # Check senso di urgenza estremo
        urgency_words = ['urgent', 'urgente', 'immediate', 'immediato', 'now', 'adesso']
        urgency_count = sum(1 for word in urgency_words if word in full_text)
        if urgency_count >= 3:
            result.add_reason("⚠️  Senso di urgenza valutato come eccessivo nel messaggio", 10)
        
        return result


    def check_dangerous_attachments(self) -> CheckResult:
        # Controlla allegati pericolosi andando a verificare le estensioni piu pericolose
        result = CheckResult("Dangerous Attachments", 0, 40)
        
        dangerousfound = []
        
        for part in self.message.walk():
            filename = part.get_filename()
            if filename:
                file_ext = Path(filename).suffix.lower()
                if file_ext in self.DANGEROUS_EXTENSIONS:
                    dangerousfound.append(filename)
        
        if dangerousfound:
            result.add_reason(
                f"🚨  {len(dangerousfound)} allegati pericolosi trovati: {', '.join(dangerousfound)}",
                20 * len(dangerousfound)
            )
        else:
            has_attachments = any(
                part.get_filename() for part in self.message.walk()
            )
            if has_attachments:
                result.add_reason("✓  Allegati presenti ma non pericolosi", 0)
            else:
                result.add_reason("ℹ️  Nessun allegato presente", 0)
        
        return result


    def check_suspicious_links(self) -> CheckResult:
        # Analizza i link sospetti nel body
        result = CheckResult("Suspicious Links", 0, 50)
        # Controllo link sospetti
        body_text = self._get_body_text()
        links = self._extract_links(body_text)
        
        if not links:
            result.add_reason("ℹ️  Nessun link trovato", 0)
            return result
        
        from_email = self._extract_email(self.message.get('From', ''))
        sender_domain = from_email.split('@')[-1].lower() if from_email else ''
        
        raw_ip_links = 0
        punycode_links = 0
        mismatched_domains = 0
        
        for link in links:
            parsed = urlparse(link)
            
            # Check per IP raw
            if self._is_ip_address(parsed.netloc):
                raw_ip_links += 1
            
            # Check per punycode
            if 'xn--' in parsed.netloc:
                punycode_links += 1
            
            # Check mismatch dominio
            link_domain = parsed.netloc.lower()
            if sender_domain and sender_domain not in link_domain:
                mismatched_domains += 1
        
        if raw_ip_links > 0:
            result.add_reason(
                f"🚨  {raw_ip_links} link con indirizzo IP raw (molto sospetto)",
                20
            )
        
        if punycode_links > 0:
            result.add_reason(
                f"⚠️  {punycode_links} link in Punycode (possibile IDN spoofing)",
                15
            )
        
        if mismatched_domains > 0 and sender_domain:
            ratio = mismatched_domains / len(links)
            if ratio > 0.8:
                result.add_reason(
                    f"🚨  {mismatched_domains}/{len(links)} link puntano a domini diversi dal mittente",
                    15
                )
            elif ratio > 0.5:
                result.add_reason(
                    f"⚠️  {mismatched_domains}/{len(links)} link puntano a domini esterni",
                    10
                )
        
        return result


    def analyze(self):
        # Mostro un disclaimer
        print("\n" + "*"*100)
        print("""**DISCLAIMER**:Questo script è stato realizzato
               per scopi didattici durante il corso di Cybersecurity2025
               organizzato ed offerto da FDA (Fastweb Digital Academy) 
              
               Non è da considerarsi come un vero e proprio tool per la sicurezza
               e sopratutto non va assolutamente utilizzato in ambiti professionali.
              
               Tutti gli score attribuiti nei risk assessment cosi come l'analisi 
               euristica sono assegnati in modo arbitrario e fondati sulle conoscenze 
               di base nell'ambito sicurezza informatica di chi ha scritto questo 
               script -in un paio di serate tra l'altro- e quindi non si tratta né di valori 
               ponderati secondo una validazione empirica né calibrati su dataset reali.
               
               Chiunque prenderà decisioni critiche basandosi sui risultati di questo script 
               lo farà a proprio rischio e pericolo.""")
        print("*"*100)
        
        # Pausa per leggere il disclaimer
        user_input = input("\n🔑 Premere SOLO INVIO per ACCETTARE e continuare con l'analisi (qualsiasi altro tasto seguito da INVIO per RIFIUTARE E TERMINARE LO SCRIPT): ")
        
        # Controlla se l'utente ha accettato il disclaimer
        if user_input.strip() != "":
            print("\n❌ Disclaimer NON accettato. Programma terminato.")
            print("👋 Arrivederci!")
            return
        
        # Pulisce lo schermo dopo l'accettazione del disclaimer
        os.system('cls' if os.name == 'nt' else 'clear')

        # Eseguiamo tutti i controlli uno dopo l'altro
        if not self.load_email():
            return
        
        print("\n" + "="*70)
        print("🔍 ANALISI EMAIL PER RILEVAMENTO PHISHING")
        print("="*70)
        print(f"\n📧 File: {self.eml_path.name}")
        print(f"📨 Subject: {self.message.get('Subject', 'N/A')}")
        print(f"👤 From: {self.message.get('From', 'N/A')}")
        print(f"📅 Date: {self.message.get('Date', 'N/A')}\n")
        
        # Esegue i controlli
        self.results.append(self.check_spf())
        self.results.append(self.check_dkim())
        self.results.append(self.check_dmarc())
        self.results.append(self.check_reply_to_mismatch())
        self.results.append(self.check_suspicious_content())
        self.results.append(self.check_suspicious_links())
        self.results.append(self.check_dangerous_attachments())

        # Calcola score totale
        for result in self.results:
            self.total_score += result.score
            self.max_total_score += result.max_score
            
        # Mostra risultati
        self._print_results()

    
    def _print_results(self):
        # Stampa i risultati dell'analisi
        print("="*70)
        print("📊 RISULTATI DETTAGLIATI")
        print("="*70 + "\n")
        
        for result in self.results:
            print(f"🔸 {result.check_name}")
            print(f"   Score: {result.score}/{result.max_score}")
            for reason in result.reasons:
                print(f"   {reason}")
            print()
        
        # Aggiungere Calcolo Score finale

        print("="*70)
        print("🎯 VALUTAZIONE FINALE ")
        print("="*70)
        print(f"\n⚡ Score Totale: {self.total_score}/{self.max_total_score}")
        
        percentage = (self.total_score / self.max_total_score * 100) if self.max_total_score > 0 else 0
        
        if percentage >= 70:
            risk_level = "🔴 RISCHIO MOLTO ALTO"
            verdict = "PHISHING MOLTO PROBABILE - ELIMINA IMMEDIATAMENTE e/o UTILIZZA UN SOFTWARE DEDICATO PER CONFERMA"
        elif percentage >= 50:
            risk_level = "🟠 RISCHIO ALTO"
            verdict = "PHISHING PROBABILE - ESTREMA CAUTELA"
        elif percentage >= 30:
            risk_level = "🟡 RISCHIO MEDIO"
            verdict = "EMAIL SOSPETTA - VERIFICARE ATTENTAMENTE"
        elif percentage >= 15:
            risk_level = "🟢 RISCHIO BASSO"
            verdict = "Email probabilmente legittima ma con qualche anomalia, è raccomandato l'uso del cervello"
        else:
            risk_level = "✅ RISCHIO MINIMO"
            verdict = "L'Email sembra legittima (ma ricordati che lo script non è infallibile...)"
        
        print(f"📈 Percentuale: {percentage:.1f}%")
        print(f"🚦 Livello di Rischio: {risk_level}")
        print(f"⚖️  Verdetto: {verdict}")
        print("\n" + "="*70 + "\n")
  

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