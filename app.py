print("\n>>> SİBER GÜVENLİK ULTIMATE (RANSOMWARE EKLENDİ) YÜKLENİYOR... <<<\n")

from flask import Flask, render_template, request, redirect, send_file
import math, hashlib, socket, os, sqlite3, time, itertools, random, json, re, glob
from datetime import datetime
from PIL import Image
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet  # GERÇEK ŞİFRELEME KÜTÜPHANESİ

app = Flask(__name__)

# Ayarlar
UPLOAD_FOLDER = 'static/uploads'
SAFE_ZONE = 'static/safe_zone'  # Ransomware sadece burayı etkiler
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'super_gizli_key'

# Klasörleri Oluştur
for folder in ['static', UPLOAD_FOLDER, SAFE_ZONE]:
    if not os.path.exists(folder): os.makedirs(folder)

# Ransomware İçin Anahtar (Normalde saldırganın sunucusunda olur)
KEY_FILE = 'static/ransom.key'
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open(KEY_FILE, 'rb') as key_file:
    CIPHER = Fernet(key_file.read())

xss_comments = []


# --- BLOCKCHAIN ---
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index, self.timestamp, self.data, self.previous_hash = index, timestamp, data, previous_hash
        self.hash = self.calculate_hash()
        self.is_valid = True

    def calculate_hash(self):
        return hashlib.sha256(
            json.dumps({"i": self.index, "t": self.timestamp, "d": self.data, "p": self.previous_hash},
                       sort_keys=True).encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [Block(0, str(datetime.now()), "Genesis", "0")]

    def add_log(self, data):
        self.chain.append(Block(len(self.chain), str(datetime.now()), data, self.chain[-1].hash))

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i - 1].hash: return False, "Zincir KOPUK!"
            if self.chain[i].hash != self.chain[i].calculate_hash(): return False, "Veri DEĞİŞTİRİLMİŞ!"
        return True, "Zincir Güvenli"


guvenli_loglar = Blockchain()


# --- YENİ MODÜL 12: RANSOMWARE ---
def get_safe_files():
    # Sadece safe_zone içindeki dosyaları listele
    files = []
    for filepath in glob.glob(os.path.join(SAFE_ZONE, '*')):
        filename = os.path.basename(filepath)
        status = "ŞİFRELİ 🔒" if filename.endswith('.locked') else "TEMİZ ✅"
        files.append({"name": filename, "status": status})
    return files


def encrypt_files():
    count = 0
    # Safe zone'daki tüm dosyaları bul
    for filepath in glob.glob(os.path.join(SAFE_ZONE, '*')):
        if not filepath.endswith('.locked'):
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()  # Oku
                encrypted_data = CIPHER.encrypt(data)  # Şifrele
                with open(filepath + '.locked', 'wb') as f:
                    f.write(encrypted_data)  # Yeni dosyayı yaz
                os.remove(filepath)  # Eski dosyayı sil
                count += 1
            except:
                pass
    return count


def decrypt_files():
    count = 0
    for filepath in glob.glob(os.path.join(SAFE_ZONE, '*.locked')):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            decrypted_data = CIPHER.decrypt(data)  # Şifreyi Çöz
            original_path = filepath.replace('.locked', '')
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            os.remove(filepath)
            count += 1
        except:
            pass
    return count


# --- AI PHISHING ---
def phishing_analizi(url):
    skor = 0;
    sebepler = []
    if len(url) > 75: skor += 20; sebepler.append("Uzun URL")
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): skor += 30; sebepler.append("IP Bazlı URL")
    if "@" in url: skor += 25; sebepler.append("@ Yönlendirmesi")
    if not url.startswith("https://"): skor += 10; sebepler.append("HTTPS Yok")
    risk = "YÜKSEK" if skor > 70 else "ORTA" if skor > 40 else "DÜŞÜK"
    return {"url": url, "skor": min(skor, 100), "risk": risk, "sebepler": sebepler}


# --- YARDIMCI FONKSİYONLAR ---
def hesapla_entropy(p):
    if not p: return 0, 0, 0
    h = 0
    if any(c.islower() for c in p): h += 26
    if any(c.isupper() for c in p): h += 26
    if any(c.isdigit() for c in p): h += 10
    if any(not c.isalnum() for c in p): h += 32
    return round(len(p) * math.log2(max(1, h)), 2), (max(1, h) ** len(p)) / 1000000000, h


def portlari_tara(ip):
    res = []
    for p, n in {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "SQL"}.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            s.settimeout(0.2)
            if s.connect_ex((ip, p)) == 0:
                res.append({'port': p, 'servis': n, 'durum': 'AÇIK', 'renk': 'green'})
            else:
                res.append({'port': p, 'servis': n, 'durum': 'KAPALI', 'renk': 'red'})
            s.close()
        except:
            pass
    return res


def trafik_olustur():
    pkts = [
        {"no": i + 100, "zaman": datetime.now().strftime("%H:%M:%S"), "kaynak": f"192.168.1.{random.randint(2, 50)}",
         "hedef": "8.8.8.8", "protokol": "TCP", "durum": "normal", "bilgi": "Data"} for i in range(15)]
    pkts.append({"no": 999, "zaman": datetime.now().strftime("%H:%M:%S"), "kaynak": "45.33.22.11", "hedef": "Server",
                 "protokol": "HTTP", "durum": "tehlike", "bilgi": "SQL Injection Detected"})
    return pkts


def sezar(txt, key, mode):
    res = ""
    if mode == 'coz': key = -key
    for c in txt:
        if c.isalpha():
            res += chr((ord(c) - (65 if c.isupper() else 97) + key) % 26 + (65 if c.isupper() else 97))
        else:
            res += c
    return res


def brute(target):
    start = time.time();
    count = 0
    for l in range(1, 6):
        for p in itertools.product("0123456789", repeat=l):
            count += 1
            if "".join(p) == target: return count, round(time.time() - start, 5)
    return count, 0


# Steganografi
def genData(data): return [format(ord(i), '08b') for i in data]


def modPix(pix, data):
    datalist = genData(data);
    lendata = len(datalist);
    imdata = iter(pix)
    for i in range(lendata):
        pixels = [value for value in next(imdata)[:3] + next(imdata)[:3] + next(imdata)[:3]]
        for j in range(0, 8):
            if (datalist[i][j] == '0') and (pixels[j] % 2 != 0):
                pixels[j] -= 1
            elif (datalist[i][j] == '1') and (pixels[j] % 2 == 0):
                pixels[j] -= 1 if pixels[j] != 0 else -1
        pixels[-1] = 0 if (i == lendata - 1) else 1
        yield from [tuple(pixels[0:3]), tuple(pixels[3:6]), tuple(pixels[6:9])]


def encode_enc(newimg, data):
    w = newimg.size[0];
    (x, y) = (0, 0)
    for pixel in modPix(newimg.getdata(), data):
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0; y += 1
        else:
            x += 1


def decode_dec(image):
    image_data = iter(image.getdata());
    data = ''
    while True:
        pixels = [value for value in next(image_data)[:3] + next(image_data)[:3] + next(image_data)[:3]]
        binstr = ''.join(['0' if i % 2 == 0 else '1' for i in pixels[:8]])
        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0): return data


# --- ROTALAR ---
@app.route('/')
def home(): return render_template('index.html')


@app.route('/parola', methods=['GET', 'POST'])
def parola():
    res = None
    if request.method == 'POST':
        p = request.form.get('kullanici_parolasi')
        e, s, h = hesapla_entropy(p)
        guvenli_loglar.add_log(f"Parola: {p}")
        res = {"girilen": p, "entropy": e, "sure": f"{int(s)} saniye", "havuz": h}
    return render_template('parola.html', sonuc=res)


@app.route('/hash', methods=['GET', 'POST'])
def hash_page():
    res = None
    if request.method == 'POST':
        m1, m2 = request.form.get('metin1'), request.form.get('metin2')
        h1, h2 = hashlib.sha256(m1.encode()).hexdigest(), hashlib.sha256(m2.encode()).hexdigest()
        diff = sum(1 for a, b in zip(h1, h2) if a != b)
        res = {"metin1": m1, "hash1": h1, "metin2": m2, "hash2": h2, "degisim": int((diff / 64) * 100)}
    return render_template('hash.html', sonuc=res)


@app.route('/port', methods=['GET', 'POST'])
def port():
    res = None;
    ip = ""
    if request.method == 'POST':
        ip = request.form.get('hedef_ip')
        res = portlari_tara(ip)
        guvenli_loglar.add_log(f"Port: {ip}")
    return render_template('port.html', sonuclar=res, ip=ip, rapor="static/rapor.txt")


@app.route('/ids')
def ids():
    pkts = trafik_olustur()
    cnt = sum(1 for p in pkts if p['durum'] == 'tehlike')
    if cnt > 0: guvenli_loglar.add_log(f"IDS: {cnt} tehdit")
    return render_template('ids.html', paketler=pkts, tehdit_sayisi=cnt)


@app.route('/blockchain')
def blockchain():
    ok, msg = guvenli_loglar.validate_chain()
    return render_template('blockchain.html', chain=guvenli_loglar.chain, durum=ok, mesaj=msg)


@app.route('/blockchain/tamper', methods=['POST'])
def tamper():
    if len(guvenli_loglar.chain) > 1: guvenli_loglar.chain[1].data = "HACKED!"
    return redirect('/blockchain')


@app.route('/sifreleme', methods=['GET', 'POST'])
def sifreleme():
    res = None;
    txt = ""
    if request.method == 'POST':
        txt = request.form.get('metin');
        key = int(request.form.get('anahtar'));
        mode = request.form.get('islem')
        res = {"cikti": sezar(txt, key, mode), "islem": mode, "anahtar": key}
    return render_template('sifreleme.html', sonuc=res, varsayilan_metin=txt)


@app.route('/steganografi', methods=['GET', 'POST'])
def steganografi():
    msg = "";
    dl = None;
    dec = None
    if request.method == 'POST':
        f = request.files.get('dosya')
        if f:
            fn = secure_filename(f.filename);
            fp = os.path.join(app.config['UPLOAD_FOLDER'], fn);
            f.save(fp)
            if request.form.get('islem') == 'gizle':
                try:
                    img = Image.open(fp);
                    new = img.copy();
                    encode_enc(new, request.form.get('gizli_metin'))
                    new_n = "gizli_" + fn;
                    new.save(os.path.join(app.config['UPLOAD_FOLDER'], new_n), "PNG")
                    msg = "Gizlendi";
                    dl = f"static/uploads/{new_n}";
                    guvenli_loglar.add_log(f"Stego Gizle: {fn}")
                except:
                    msg = "Hata"
            else:
                try:
                    dec = decode_dec(Image.open(fp)); guvenli_loglar.add_log("Stego Oku")
                except:
                    dec = "Okunamadı"
    return render_template('steganografi.html', mesaj=msg, indirme=dl, cozulmus=dec)


@app.route('/sqli', methods=['GET', 'POST'])
def sqli():
    msg = None;
    ok = False;
    log = ""
    if request.method == 'POST':
        u = request.form.get('username')
        log = f"SELECT * FROM users WHERE user='{u}' AND pass='...'"
        if "' OR" in u or "--" in u:
            msg = "HACKED!"; ok = True; guvenli_loglar.add_log(f"SQLi: {u}")
        else:
            msg = "Başarısız"; ok = False
    return render_template('sqli.html', mesaj=msg, basari=ok, log=log)


@app.route('/xss', methods=['GET', 'POST'])
def xss():
    global xss_comments
    if request.method == 'POST':
        if 'temizle' in request.form:
            xss_comments = []
        else:
            c = request.form.get('yorum')
            xss_comments.append(c)
            guvenli_loglar.add_log(f"XSS: {c[:10]}")
        return redirect('/xss')
    return render_template('xss.html', yorumlar=xss_comments)


@app.route('/bruteforce', methods=['GET', 'POST'])
def bruteforce():
    res = None
    if request.method == 'POST':
        tgt = request.form.get('hedef_sifre')
        cnt, tm = brute(tgt)
        res = {"hedef": tgt, "deneme": cnt, "sure": tm, "hiz": int(cnt / (tm + 0.0001))}
        guvenli_loglar.add_log(f"Brute: {tgt}")
    return render_template('bruteforce.html', sonuc=res)


@app.route('/phishing', methods=['GET', 'POST'])
def phishing():
    analiz = None
    if request.method == 'POST':
        url = request.form.get('url')
        analiz = phishing_analizi(url)
        guvenli_loglar.add_log(f"Phishing: {url} ({analiz['risk']})")
    return render_template('phishing.html', analiz=analiz)


# --- YENİ ROUTE: RANSOMWARE ---
@app.route('/ransomware', methods=['GET', 'POST'])
def ransomware():
    msg = ""
    if request.method == 'POST':
        islem = request.form.get('islem')
        if islem == 'upload':
            f = request.files.get('dosya')
            if f:
                f.save(os.path.join(SAFE_ZONE, secure_filename(f.filename)))
                msg = "Dosya Yüklendi. Henüz Güvende."
        elif islem == 'encrypt':
            count = encrypt_files()
            msg = f"SALDIRI BAŞLATILDI: {count} Dosya Şifrelendi!"
            guvenli_loglar.add_log(f"RANSOMWARE: {count} dosya kilitlendi!")
        elif islem == 'decrypt':
            key = request.form.get('key')
            # Gerçek bir ransomware'de key kontrolü sunucuda yapılır
            count = decrypt_files()
            msg = f"ŞİFRE ÇÖZÜLDÜ: {count} Dosya Kurtarıldı!"
            guvenli_loglar.add_log("RANSOMWARE: Dosyalar kurtarıldı")

    files = get_safe_files()
    return render_template('ransomware.html', files=files, mesaj=msg)


if __name__ == '__main__':
    app.run(debug=True, port=5003)