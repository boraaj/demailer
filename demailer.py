import email
import sys
import re
from tabulate import tabulate


def analyze_header(eml_path):
    """
    Analize the headers from a .eml file and displays a security report
    """

    try:
        with open(eml_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
    except FileNotFoundError:
        print(f"❌ Error: File '{eml_path}' not found ❌ ")
        return
    except Exception as e:
        print(f"❌ There was an error reading the file: {e}")
        return

    print("\n" + "="*50)
    print("🔎 HEADERS ANALYSIS")
    print("="*50)

    basic_info = [
        ["From", msg.get('From')],
        ["To", msg.get('To')],
        ["Subject", msg.get('Subject')],
        ["Date", msg.get('Date')],
        ["Message-ID", msg.get('Message-ID')]
    ]

    print("\n📋 BASIC INFO")
    print(tabulate(basic_info, tablefmt="grid"))

    received_headers = msg.get_all('Received', [])
    received_headers.reverse()

    email_route = []

    print("\n🗺️ Email Route (Origin to Destiny)")

    if received_headers:
        for i, header in enumerate(received_headers):
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
            ip_str = ", ".join(ips) if ips else "IP Not Found"
            server_info = header.split(";")[0].replace('\n', ' ').strip()
            email_route.append([f"Hop {i+1}", server_info, ip_str])
        print(tabulate(email_route, headers=[
              "Hop", "Server", "IPs"], tablefmt="grid", maxcolwidths=[None, 70, None]))
    else:
        print("'Received' Headers not found")

    auth_results = msg.get('Authentication-Results', 'Not Found')

    print("\n🛡️ AUTH RESULTS")

    spf_status = "Not Found"
    if 'spf=pass' in auth_results:
        spf_status = "✅ Pass"
    elif 'spf=fail' in auth_results:
        spf_status = "❌ Fail"
    elif 'spf=softfail' in auth_results:
        spf_status = "⚠️ Softfail"
    elif 'spf=neutral' in auth_results:
        spf_status = "❓ Neutral"

    dkim_status = "Not Found"
    if 'dkim=pass' in auth_results:
        dkim_status = "✅ Pass"
    elif 'dkim=fail' in auth_results:
        dkim_status = "❌ Fail"

    dmarc_status = "Not Found"
    if 'dmarc=pass' in auth_results:
        dmarc_status = "✅ Pass"
    elif 'dmarc=fail' in auth_results:
        dmarc_status = "❌ Fail"

    auth_table = [
        ["SPF (Sender Policy Framework)", spf_status],
        ["DKIM (DomainKeys Identified Mail)", dkim_status],
        ["DMARC (Domain-based Message Auth)", dmarc_status]
    ]

    print(tabulate(auth_table, headers=["Check", "Result"], tablefmt="grid"))
    print("\n" + "="*50)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Use: python demailer.py <path_to_eml_file>")
    else:
        eml_file = sys.argv[1]
        analyze_header(eml_file)
