"""A freelance web designer who looks after clients' hosting, the target of
the fake-installer stealers that also grab FTP, VPN and key files: FileZilla
sites, VPN profiles, a password-manager export and client site configs."""

import base64

from .lib import HIDDEN, STORED, WORTH


def build(h):
    chrome = h.browser("Default", logins=12, cards=1)
    h.expect(f"{chrome}/Login Data", "passwords saved in Chrome", STORED, "the browser's own store")
    h.expect(f"{chrome}/Web Data", "payment card saved in Chrome", STORED, "the browser's own store")
    server = lambda: ("<Server><Host>ftp.client.example.invalid</Host><Port>21</Port><User>deploy</User>"
                      f'<Pass encoding="base64">{base64.b64encode(h.password().encode()).decode()}</Pass></Server>')
    h.plant(".config/filezilla/sitemanager.xml",
            f'<?xml version="1.0"?>\n<FileZilla3><Servers>\n{server()}\n{server()}\n</Servers></FileZilla3>\n',
            "FTP passwords saved by FileZilla", WORTH, "client server passwords, only base64-encoded")
    h.plant(".config/filezilla/recentservers.xml",
            f'<?xml version="1.0"?>\n<FileZilla3><RecentServers>\n{server()}\n</RecentServers></FileZilla3>\n',
            "FTP password in FileZilla's recent servers", WORTH, "a client server password")
    h.plant("Documents/VPN/client.ovpn",
            "client\nremote vpn.client.example.invalid 1194\n<ca>\n" + h.certificate() + "</ca>\n<key>\n" + h.pem("") + "</key>\n",
            "VPN profile with its private key inside", WORTH, "an unprotected key")
    h.plant("Documents/VPN/office.ovpn",
            "client\nremote vpn.office.example.invalid 1194\nauth-user-pass\n<ca>\n" + h.certificate() + "</ca>\n",
            "VPN profile that asks for a password", HIDDEN, "holds a public certificate only")
    h.plant("Documents/wg-office.conf",
            f"[Interface]\nPrivateKey = {base64.b64encode(h.rng.randbytes(32)).decode()}\nAddress = 10.0.0.2/32\n\n"
            f"[Peer]\nPublicKey = {base64.b64encode(h.rng.randbytes(32)).decode()}\nEndpoint = vpn.office.example.invalid:51820\n",
            "WireGuard config with its private key", WORTH, "an unprotected key")
    h.plant("Downloads/lastpass_export.csv",
            "url,username,password,totp,extra,name,grouping,fav\n" + "".join(
                f"https://client{n}.example.invalid,admin,{h.password()},,,Client {n},Work,0\n" for n in range(15)),
            "LastPass export left in Downloads", WORTH, "every password in plain text")
    h.plant("Documents/office-wifi.txt", f"Office\nWi-Fi password: {h.password(12)}\nGuest network: ask reception\n",
            "Wi-Fi password in a note", WORTH, "a real password")
    h.plant("Documents/sites/client-a/wp-config.php",
            f"<?php\ndefine('DB_NAME', 'client_a');\ndefine('DB_USER', 'client_a');\ndefine('DB_PASSWORD', '{h.password()}');\n"
            f"define('AUTH_KEY', '{h.chars(64)}');\n",
            "WordPress database password in wp-config.php", WORTH, "a real password")
    h.plant("Documents/sites/shop/.env",
            f"APP_KEY=base64:{base64.b64encode(h.rng.randbytes(32)).decode()}\nMAIL_PASSWORD={h.password()}\n"
            "DB_HOST=127.0.0.1\nDB_PASSWORD=secret\n",
            "Laravel app key and mail password in a client site's .env", WORTH, "real secrets")
    h.plant("Documents/certs/client.p12", b"\x30\x82\x09\xa9\x02\x01\x03" + h.rng.randbytes(2400),
            "PKCS#12 certificate with its key", WORTH, "holds a private key")
    h.plant("Documents/certs/server.crt", h.certificate(), "TLS certificate", HIDDEN, "public by design")
    h.plant("Documents/Signing/dev.key", h.pem("RSA"), "signing key with no passphrase", WORTH, "an unprotected key")
    h.plant("Documents/Passwords.kdbx", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00" + h.rng.randbytes(4000),
            "KeePass database", STORED, "an encrypted password database")
    h.plant("Documents/Client logins.docx", b"PK\x03\x04" + h.rng.randbytes(5000),
            "Word file of client logins", WORTH, "stealers take it; the usage guide says document contents are not read")
    h.plant("Library/Application Support/Cyberduck/Bookmarks/client-a.duck",
            '<?xml version="1.0"?>\n<plist version="1.0"><dict><key>Hostname</key><string>ftp.client.example.invalid</string>'
            "<key>Username</key><string>deploy</string></dict></plist>\n",
            "Cyberduck bookmark", HIDDEN, "the password is in the Keychain")
    h.plant("Documents/todo.txt", "- invoice client A\n- change the portal password\n- renew domain\n",
            "to-do list that mentions a password", HIDDEN, "no secret")
    h.documents("Documents/Invoices", 400)
    h.documents("Documents/sites/client-a/wp-content/uploads", 1200)
    h.tree("Documents/sites/client-a/wp-includes", 1500, (".php", ".js"), 4)
    h.tree("Documents/sites/shop/vendor", 2500, (".php",), 5)
    h.documents("Downloads", 500)
    h.documents("Desktop", 40)
    h.tree("Library/Application Support/Adobe/CoreSync", 800, (".db", ".xml"), 3, 3)
