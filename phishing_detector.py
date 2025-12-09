from pathlib import Path
from dataclasses import dataclass, field
import argparse
from typing import List
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import os
from datetime import datetime
from email.utils import parsedate_to_datetime


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
            print(f"[X][X] Errore nel caricamento del file [X][X]: {e}")
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
        result = CheckResult("SPF Validation", 0, 50)
        
        received_spf = self.message.get('Received-SPF', '')
        received_spf_lower = received_spf.lower()
        auth_results = self.message.get('Authentication-Results', '')
        auth_results_lower = auth_results.lower()
        
        if not received_spf and 'spf=' not in auth_results_lower:
            result.add_reason("⚠   Record SPF non trovato negli header", 42)
        elif 'none' in received_spf_lower or 'spf=none' in auth_results_lower:
            result.add_reason("!!   SPF NONE - Il controllo non è implementato", 42)
        elif 'fail' in received_spf_lower or 'spf=fail' in auth_results_lower:
            result.add_reason("!!   SPF FAIL - Il mittente non è autorizzato", 50)
        elif 'softfail' in received_spf_lower or 'spf=softfail' in auth_results_lower:
            result.add_reason("⚠   SPF SOFTFAIL - Mittente potenzialmente non autorizzato", 33)
        elif 'neutral' in received_spf_lower or 'spf=neutral' in auth_results_lower:
            result.add_reason("⚠   SPF NEUTRAL - Nessuna politica definita", 25)
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
                        f"!!   SPF PASS ma 2 domini non congruenti - {domain_info}", 42)
                elif len(unique_domains) > 2:
                    # 3 domini tutti diversi - punteggio negativo maggiore
                    domain_info = ', '.join([f"{name}: {domain}" for name, domain in domains_found])
                    result.add_reason(
                        f"!!   SPF PASS ma diversi domini non congruenti - {domain_info}", 50)
                else:
                    result.add_reason("✓   Domini congruenti tra SPF, MAIL FROM e From", 0)
        else:
            result.add_reason("⚠   SPF non verificabile,è consigliato un controllo manuale con altro tool dedicato", 38)
        
        return result


    def check_dkim(self) -> CheckResult:
        # Controlla la firma DKIM
        result = CheckResult("DKIM Signature", 0, 50)
        
        auth_results = self.message.get('Authentication-Results', '').lower()
        dkim_signature = self.message.get('DKIM-Signature', '')
        
        if not dkim_signature and 'dkim=' not in auth_results:
            result.add_reason("⚠   Firma DKIM assente", 30)
        elif 'dkim=fail' in auth_results:
            result.add_reason("!!   DKIM FAIL - Firma non valida", 50)
        elif 'dkim=pass' in auth_results:
            result.add_reason("✓   DKIM PASS - Firma valida", 0)
        elif 'dkim=none' in auth_results:
            result.add_reason("⚠   Firma DKIM assente", 30)
        else:
            result.add_reason("⚠   DKIM non verificabile", 26)
        
        return result


    def check_dmarc(self) -> CheckResult:
        # Controlla la policy DMARC
        result = CheckResult("DMARC Policy", 0, 50)
        
        auth_results = self.message.get('Authentication-Results', '').lower()
        
        if 'dmarc=' not in auth_results:
            result.add_reason("⚠   Risultato DMARC non trovato", 30)
        elif 'dmarc=fail' in auth_results:
            result.add_reason("!!   DMARC FAIL - Policy non rispettata", 50)
        elif 'dmarc=pass' in auth_results:
            result.add_reason("✓   DMARC PASS - Policy rispettata", 0)
        elif 'dmarc=none' in auth_results:
            result.add_reason("⚠   Risultato DMARC non trovato", 30)
        else:
            result.add_reason("⚠   DMARC non verificabile", 26)
        
        return result


    def check_reply_to_mismatch(self) -> CheckResult:
        # Controlla un eventuale mismatch tra From e Reply-To
        result = CheckResult("Reply-To Mismatch", 0, 40)
        
        from_header = self.message.get('From', '')
        reply_to = self.message.get('Reply-To', '')
        
        if not reply_to:
            result.add_reason("ℹ   Reply-To non presente (normale)", 0)
            return result
        
        # Estrai email da From e Reply-To
        from_email = self._extract_email(from_header)
        reply_email = self._extract_email(reply_to)
        
        if from_email and reply_email:
            from_domain = from_email.split('@')[-1].lower()
            reply_domain = reply_email.split('@')[-1].lower()
            
            if from_domain != reply_domain:
                result.add_reason(
                    f"!!  MISMATCH Reply-To: From={from_domain}, Reply-To={reply_domain}",
                    40
                )
            else:
                result.add_reason("✓ Reply-To corrisponde al mittente", 0)
        
        return result


    def check_date_inconsistencies(self) -> CheckResult:
        # Controlla eventuali incongruenze nella data delle email
        result = CheckResult("Date Inconsistencies", 0, 30)
        
        date_header = self.message.get('Date', '')
        
        if not date_header:
            result.add_reason("⚠   Header Date mancante", 20)
            return result
        
        try:
            # Prova a parsare la data
            email_date = parsedate_to_datetime(date_header)
            current_date = datetime.now(email_date.tzinfo) if email_date.tzinfo else datetime.now()
            
            # Calcola la differenza in giorni
            if email_date.tzinfo:
                # Se ha timezone, usa quello
                time_diff = (current_date - email_date).total_seconds() / 86400
            else:
                # Se non ha timezone, assumi UTC
                time_diff = (datetime.now() - email_date.replace(tzinfo=None)).total_seconds() / 86400
            
            # Controlla se la data è nel futuro
            if time_diff < -1:  # Più di 1 giorno nel futuro (tolleranza per fuso orario)
                days_future = abs(time_diff)
                result.add_reason(
                    f"!!  Data email nel futuro ({days_future:.1f} giorni) - molto sospetto",
                    30
                )
            # Controlla se la data è molto vecchia (più di 1 anno)
            elif time_diff > 365:
                years_old = time_diff / 365
                result.add_reason(
                    f"⚠  Data email molto vecchia ({years_old:.1f} anni fa) - possibile email archiviata o manipolata",
                    15
                )
            # Controlla se la data è molto recente ma con timestamp sospetto (es. 1970)
            elif email_date.year < 2000:
                result.add_reason(
                    f"!!  Data email sospetta (anno {email_date.year}) - possibile timestamp errato o manipolato",
                    25
                )
            else:
                result.add_reason("✓ Data email valida", 0)
                
        except (ValueError, TypeError) as e:
            # Data non parsabile o formato non valido
            result.add_reason(
                f"⚠   Formato data non valido o non parsabile: {date_header[:50]}",
                20
            )
        
        # Controlla anche eventuali discrepanze con altri header di timestamp
        received_headers = []
        for header_name, header_value in self.message.items():
            if header_name.lower().startswith('received'):
                received_headers.append(header_value)
        
        if received_headers and date_header:
            # Estrai date dai Received headers (se presenti)
            try:
                email_date = parsedate_to_datetime(date_header)
                # Cerca date nei Received headers (formato tipico: "Mon, 14 Mar 2022 16:03:25 -0700")
                received_dates = []
                for received in received_headers:
                    date_match = re.search(r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', received)
                    if date_match:
                        try:
                            # Prova a parsare la data dal Received header
                            received_date_str = date_match.group(1)
                            # Formato approssimativo per Received headers
                            received_dates.append(received_date_str)
                        except:
                            pass
                
                # Se ci sono date nei Received molto diverse dalla Date header, è sospetto
                if received_dates and len(received_dates) > 0:
                    # Nota: questo è un controllo base, potrebbe essere migliorato
                    result.add_reason("ℹ   Date nei Received headers presenti (verifica manuale consigliata)", 0)
            except:
                pass
        
        return result


    def check_hidden_bcc(self) -> CheckResult:
        # Controlla se è presente un BCC nascosto e pattern sospetti di invio massivo
        result = CheckResult("Hidden BCC Check", 0, 70)
        
        bcc = self.message.get('Bcc', '')
        to_header = self.message.get('To', '').lower()
        
        # Controlla se To contiene "undisclosed-recipients" o pattern simili
        has_undisclosed = 'undisclosed' in to_header or 'undisclosed-recipients' in to_header
        
        if bcc:
            # Estrai tutti gli indirizzi BCC (possono essercene multipli)
            bcc_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', bcc)
            if bcc_emails:
                bcc_list = ', '.join(bcc_emails[:3])  # Mostra solo i primi 3 per brevità
                if len(bcc_emails) > 3:
                    bcc_list += f" ... (+{len(bcc_emails)-3} altri)"
                
                # Pattern molto sospetto: undisclosed-recipients + BCC
                if has_undisclosed:
                    result.add_reason(
                        f"!!  PATTERN SOSPETTO: To contiene 'undisclosed-recipients' e BCC presente ({len(bcc_emails)} destinatario/i)",
                        70
                    )
                    result.add_reason(
                        f"    Questo indica invio massivo: tutti i destinatari sono in BCC per nascondere la lista completa",
                        0
                    )
                    result.add_reason(
                        f"    BCC trovato/i: {bcc_list}",
                        0
                    )
                else:
                    # BCC presente ma To normale - comunque sospetto
                    result.add_reason(
                        f"⚠   BCC nascosto trovato ({len(bcc_emails)} destinatario/i): {bcc_list}",
                        49
                    )
                    result.add_reason(
                        f"    Nota: Sei tu nel BCC - indica possibile invio massivo/spam",
                        0
                    )
            else:
                result.add_reason("⚠   Header BCC presente ma formato non riconosciuto", 28)
        elif has_undisclosed:
            # Solo undisclosed-recipients senza BCC visibile (potrebbe essere stato rimosso)
            result.add_reason(
                "⚠   To contiene 'undisclosed-recipients' - lista destinatari nascosta",
                21
            )
        else:
            result.add_reason("✓ Nessun BCC nascosto trovato", 0)
        
        return result


    def check_scl_score(self) -> CheckResult:
        # Controlla e valuta lo SCL (Spam Confidence Level) score
        result = CheckResult("SCL Score", 0, 40)
        
        # Cerca SCL in vari header possibili
        scl_value = None
        
        # Microsoft Exchange/Outlook
        antispam = self.message.get('X-Microsoft-Antispam', '')
        if antispam:
            scl_match = re.search(r'SCL:(\d+)', antispam, re.IGNORECASE)
            if scl_match:
                scl_value = int(scl_match.group(1))
        
        # Altri possibili header
        if scl_value is None:
            x_scl = self.message.get('X-SCL', '')
            if x_scl:
                try:
                    scl_value = int(x_scl.strip())
                except ValueError:
                    pass
        
        if scl_value is None:
            result.add_reason("ℹ   SCL score non trovato negli header", 0)
        else:
            # SCL va da -1 a 9, dove:
            # -1 = Bypass filtering
            # 0-1 = Non spam
            # 2-4 = Sospetto
            # 5-6 = Probabile spam
            # 7-9 = Spam confermato
            if scl_value >= 7:
                result.add_reason(
                    f"!!  SCL score molto alto ({scl_value}/9) - Spam confermato",
                    40
                )
            elif scl_value >= 5:
                result.add_reason(
                    f"!!  SCL score alto ({scl_value}/9) - Probabile spam",
                    32
                )
            elif scl_value >= 2:
                result.add_reason(
                    f"⚠  SCL score moderato ({scl_value}/9) - Sospetto",
                    16
                )
            elif scl_value >= 0:
                result.add_reason(
                    f"✓  SCL score basso ({scl_value}/9) - Non spam",
                    0
                )
            else:
                result.add_reason(
                    f"ℹ   SCL score bypass ({scl_value}) - Filtro bypassato",
                    0
                )
        
        return result


    def check_multiple_ara(self) -> CheckResult:
        # Controlla se sono presenti molteplici codici ARA (Authentication-Results-Action)
        result = CheckResult("Multiple ARA Codes", 0, 60)
        
        # Cerca tutti gli header Authentication-Results
        auth_results_headers = []
        for header_name, header_value in self.message.items():
            if header_name.lower() == 'authentication-results':
                auth_results_headers.append(header_value)
        
        # Cerca anche codici ARA nell'header X-Microsoft-Antispam (formato ARA:xxx|yyy|zzz)
        ara_codes_count = 0
        antispam_header = self.message.get('X-Microsoft-Antispam', '')
        if antispam_header:
            ara_match = re.search(r'ARA:([^;]+)', antispam_header, re.IGNORECASE)
            if ara_match:
                ara_values = ara_match.group(1).strip()
                # Conta i codici ARA separati da |
                ara_codes = [code.strip() for code in ara_values.split('|') if code.strip()]
                ara_codes_count = len(ara_codes)
        
        # Conta i codici ARA (action) diversi negli header Authentication-Results
        ara_actions = set()
        for header_value in auth_results_headers:
            # Cerca pattern come "action=xxx" o "ara=xxx"
            ara_match = re.search(r'(?:action|ara)=(\w+)', header_value, re.IGNORECASE)
            if ara_match:
                ara_actions.add(ara_match.group(1).lower())
        
        # Valutazione: considera sia header Authentication-Results che codici ARA
        # Priorità ai codici ARA se presenti, altrimenti usa gli header
        if ara_codes_count > 0:
            # Valutazione basata sui codici ARA in X-Microsoft-Antispam
            if ara_codes_count >= 3:
                result.add_reason(
                    f"!!  {ara_codes_count} codici ARA trovati in X-Microsoft-Antispam (molto sospetto)",
                    60
                )
            elif ara_codes_count == 2:
                result.add_reason(
                    f"⚠  {ara_codes_count} codici ARA trovati in X-Microsoft-Antispam",
                    30
                )
            else:
                result.add_reason("✓ Singolo codice ARA trovato in X-Microsoft-Antispam (normale)", 0)
        elif len(auth_results_headers) == 0:
            result.add_reason("ℹ   Nessun header Authentication-Results o codice ARA trovato", 0)
        elif len(auth_results_headers) == 1:
            result.add_reason("✓ Singolo header Authentication-Results trovato (normale)", 0)
        else:
            # Valutazione basata sugli header Authentication-Results
            if len(auth_results_headers) >= 3:
                # 3+ header sono molto sospetti
                if len(ara_actions) > 1:
                    result.add_reason(
                        f"!!  {len(auth_results_headers)} header Authentication-Results trovati con azioni diverse: {', '.join(ara_actions)} (molto sospetto)",
                        60
                    )
                else:
                    result.add_reason(
                        f"!!  {len(auth_results_headers)} header Authentication-Results trovati (molto sospetto)",
                        60
                    )
            elif len(auth_results_headers) == 2:
                # 2 header possono essere normali o sospetti a seconda delle azioni
                if len(ara_actions) > 1:
                    result.add_reason(
                        f"⚠  {len(auth_results_headers)} header Authentication-Results con azioni diverse: {', '.join(ara_actions)}",
                        45
                    )
                else:
                    result.add_reason(
                        f"⚠  {len(auth_results_headers)} header Authentication-Results trovati",
                        30
                    )
        
        return result


    def check_bcl_score(self) -> CheckResult:
        # Controlla e valuta il BCL (Bulk Confidence Level) score
        result = CheckResult("BCL Score", 0, 30)
        
        # Cerca BCL in vari header possibili
        bcl_value = None
        
        # Microsoft Exchange/Outlook
        antispam = self.message.get('X-Microsoft-Antispam', '')
        if antispam:
            bcl_match = re.search(r'BCL:(\d+)', antispam, re.IGNORECASE)
            if bcl_match:
                bcl_value = int(bcl_match.group(1))
        
        # Altri possibili header
        if bcl_value is None:
            x_bcl = self.message.get('X-BCL', '')
            if x_bcl:
                try:
                    bcl_value = int(x_bcl.strip())
                except ValueError:
                    pass
        
        if bcl_value is None:
            result.add_reason("ℹ   BCL score non trovato negli header", 0)
        else:
            # BCL va tipicamente da 0 a 9, dove:
            # 0-3 = Bassa probabilità di bulk mail
            # 4-6 = Media probabilità di bulk mail
            # 7-9 = Alta probabilità di bulk mail (spam/newsletter)
            if bcl_value >= 7:
                result.add_reason(
                    f"⚠  BCL score molto alto ({bcl_value}/9) - Alta probabilità di bulk mail/spam",
                    30
                )
            elif bcl_value >= 4:
                result.add_reason(
                    f"⚠  BCL score moderato ({bcl_value}/9) - Media probabilità di bulk mail",
                    15
                )
            elif bcl_value >= 0:
                result.add_reason(
                    f"✓  BCL score basso ({bcl_value}/9) - Bassa probabilità di bulk mail",
                    0
                )
        
        return result


    def check_suspicious_content(self) -> CheckResult:
        #Tenta una sorta di analisi euristica del contenuto valutando le  parole sospette
        result = CheckResult("Suspicious Content", 0, 60)
        
        subject = self.message.get('Subject', '').lower()
        body_text = self._get_body_text().lower()
        full_text = f"{subject} {body_text}"
        
        found_keywords = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in full_text:
                found_keywords.append(keyword)
        
        if len(found_keywords) >= 5:
            result.add_reason(
                f"!!  {len(found_keywords)} parole sospette trovate, un pò troppe (phishing probabile)",
                45
            )
        elif len(found_keywords) >= 3:
            result.add_reason(
                f"⚠  {len(found_keywords)} parole sospette trovate: {', '.join(found_keywords[:5])}",
                30
            )
        elif len(found_keywords) >= 1:
            result.add_reason(
                f"⚠  Alcune parole sospette: {', '.join(found_keywords)}",
                15
            )
        else:
            result.add_reason("✓ Nessuna parola particolarmente sospetta", 0)
        
        # Check senso di urgenza estremo
        urgency_words = ['urgent', 'urgente', 'immediate', 'immediato', 'now', 'adesso']
        urgency_count = sum(1 for word in urgency_words if word in full_text)
        if urgency_count >= 3:
            result.add_reason("⚠  Senso di urgenza valutato come eccessivo nel messaggio", 15)
        
        return result


    def check_dangerous_attachments(self) -> CheckResult:
        # Controlla allegati pericolosi andando a verificare le estensioni piu pericolose
        result = CheckResult("Dangerous Attachments", 0, 60)
        
        dangerousfound = []
        
        for part in self.message.walk():
            filename = part.get_filename()
            if filename:
                file_ext = Path(filename).suffix.lower()
                if file_ext in self.DANGEROUS_EXTENSIONS:
                    dangerousfound.append(filename)
        
        if dangerousfound:
            # Calcola punteggio: massimo 60 punti, 30 punti per allegato (max 2 allegati)
            score_per_attachment = 30
            total_score = min(score_per_attachment * len(dangerousfound), 60)
            result.add_reason(
                f"!!  {len(dangerousfound)} allegati pericolosi trovati: {', '.join(dangerousfound)}",
                total_score
            )
        else:
            has_attachments = any(
                part.get_filename() for part in self.message.walk()
            )
            if has_attachments:
                result.add_reason("✓  Allegati presenti ma non pericolosi", 0)
            else:
                result.add_reason("ℹ   Nessun allegato presente", 0)
        
        return result


    def check_suspicious_links(self) -> CheckResult:
        # Analizza i link sospetti nel body
        result = CheckResult("Suspicious Links", 0, 60)
        # Controllo link sospetti
        body_text = self._get_body_text()
        links = self._extract_links(body_text)
        
        if not links:
            result.add_reason("ℹ   Nessun link trovato", 0)
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
                f"!!  {raw_ip_links} link con indirizzo IP raw (molto sospetto)",
                24
            )
        
        if punycode_links > 0:
            result.add_reason(
                f"⚠  {punycode_links} link in Punycode (possibile IDN spoofing)",
                18
            )
        
        if mismatched_domains > 0 and sender_domain:
            ratio = mismatched_domains / len(links)
            if ratio > 0.8:
                result.add_reason(
                    f"!!  {mismatched_domains}/{len(links)} link puntano a domini diversi dal mittente",
                    18
                )
            elif ratio > 0.5:
                result.add_reason(
                    f"⚠  {mismatched_domains}/{len(links)} link puntano a domini esterni",
                    12
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
        user_input = input("\n[KEY] Premere SOLO INVIO per ACCETTARE e continuare con l'analisi (qualsiasi altro tasto seguito da INVIO per RIFIUTARE E TERMINARE LO SCRIPT): ")
        
        # Controlla se l'utente ha accettato il disclaimer
        if user_input.strip() != "":
            print("\n[X] Disclaimer NON accettato. Programma terminato.")
            print("Arrivederci!")
            return
        
        # Pulisce lo schermo dopo l'accettazione del disclaimer
        os.system('cls' if os.name == 'nt' else 'clear')

        # Eseguiamo tutti i controlli uno dopo l'altro
        if not self.load_email():
            return
        
        print("\n" + "="*70)
        print("→ ANALISI EMAIL PER RILEVAMENTO PHISHING")
        print("="*70)
        print(f"\n[EMAIL] File: {self.eml_path.name}")
        print(f"[SUBJECT] Subject: {self.message.get('Subject', 'N/A')}")
        print(f"[USER] From: {self.message.get('From', 'N/A')}")
        print(f"[DATE] Date: {self.message.get('Date', 'N/A')}\n")
        
        # Esegue i controlli
        self.results.append(self.check_spf())
        self.results.append(self.check_dkim())
        self.results.append(self.check_dmarc())
        self.results.append(self.check_reply_to_mismatch())
        self.results.append(self.check_date_inconsistencies())
        self.results.append(self.check_hidden_bcc())
        self.results.append(self.check_scl_score())
        self.results.append(self.check_multiple_ara())
        self.results.append(self.check_bcl_score())
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
        print("■ RISULTATI DETTAGLIATI")
        print("="*70 + "\n")
        
        for result in self.results:
            print(f"◆ {result.check_name}")
            print(f"   Score: {result.score}/{result.max_score}")
            for reason in result.reasons:
                print(f"   {reason}")
            print()
        
        # Aggiungere Calcolo Score finale

        print("="*70)
        print("★ VALUTAZIONE FINALE ")
        print("="*70)
        print(f"\n⚡ Score Totale: {self.total_score}/{self.max_total_score}")
        
        percentage = (self.total_score / self.max_total_score * 100) if self.max_total_score > 0 else 0
        
        # Codici colore ANSI
        RED = '\033[91m'      # Rosso brillante
        ORANGE = '\033[31m'   # Rosso standard
        YELLOW = '\033[93m'   # Giallo brillante
        YELLOW_LIGHT = '\033[33m'  # Giallo standard
        GREEN = '\033[92m'    # Verde brillante
        RESET = '\033[0m'     # Reset colore
        
        if percentage >= 70:
            risk_level = f"{RED}● RISCHIO MOLTO ALTO{RESET}"
            verdict = "PHISHING MOLTO PROBABILE - ELIMINA IMMEDIATAMENTE e/o UTILIZZA UN SOFTWARE DEDICATO PER CONFERMA"
        elif percentage >= 50:
            risk_level = f"{ORANGE}● RISCHIO ALTO{RESET}"
            verdict = "PHISHING PROBABILE - ESTREMA CAUTELA"
        elif percentage >= 30:
            risk_level = f"{YELLOW}● RISCHIO MEDIO{RESET}"
            verdict = "EMAIL SOSPETTA - VERIFICARE ATTENTAMENTE"
        elif percentage >= 15:
            risk_level = f"{YELLOW_LIGHT}● RISCHIO BASSO{RESET}"
            verdict = "Email probabilmente legittima ma con qualche anomalia, è raccomandato l'uso del cervello"
        else:
            risk_level = f"{GREEN}● RISCHIO MINIMO{RESET}"
            verdict = "L'Email sembra legittima (ma ricordati che lo script non è infallibile...)"
        
        print(f"→ Percentuale: {percentage:.1f}%")
        print(f"→ Livello di Rischio: {risk_level}")
        print(f"→ Verdetto: {verdict}")
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