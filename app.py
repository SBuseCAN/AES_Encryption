from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64
import datetime
import io # Dosya indirme işlemi için gerekli

app = Flask(__name__)
app.secret_key = "super_gizli_flask_key"

# SQLite Veritabanı (MySQL yerine - kurulum gerektirmez)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///saglik.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# DOSYA YÜKLEME AYARLARI
UPLOAD_FOLDER = 'uploads' # Şifreli dosyaların duracağı klasör
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# --- ŞİFRELEME SINIFI ---
class SecurityManager:
    STATIC_KEY = b'12345678901234567890123456789012' 

    @staticmethod
    def encrypt(data):
        # Metin Şifreleme (Eski fonksiyonumuz)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(SecurityManager.STATIC_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        sha256 = hashlib.sha256()
        sha256.update(data.encode('utf-8'))
        
        return {
            'enc_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'hash': sha256.hexdigest()
        }

    @staticmethod
    def decrypt(enc_data_b64, iv_b64, received_hash):
        # Metin Çözme (Eski fonksiyonumuz)
        try:
            encrypted_data = base64.b64decode(enc_data_b64)
            iv = base64.b64decode(iv_b64)
            cipher = Cipher(algorithms.AES(SecurityManager.STATIC_KEY), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            try:
                unpadder = padding.PKCS7(128).unpadder()
                plain_text = unpadder.update(padded_data) + unpadder.finalize()
            except ValueError:
                return False, "KRİTİK: Şifreleme blok yapısı bozulmuş!"

            decoded_text = plain_text.decode('utf-8')
            sha256 = hashlib.sha256()
            sha256.update(decoded_text.encode('utf-8'))
            
            if sha256.hexdigest() == received_hash:
                return True, decoded_text
            else:
                return False, "Hash Uyuşmazlığı!"
        except Exception as e:
            return False, f"Veri okunamadı: {str(e)}"

    # --- YENİ: DOSYA (BYTE) ŞİFRELEME ---
    @staticmethod
    def encrypt_file_bytes(file_bytes):
        """Dosyayı binary (byte) olarak alır, şifreler ve döner."""
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_bytes) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(SecurityManager.STATIC_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Dosyayı kaydederken IV'yi dosyanın başına ekliyoruz ki çözerken kullanalım
        return iv + encrypted_data

    @staticmethod
    def decrypt_file_bytes(encrypted_file_bytes):
        """Şifreli dosya byte'larını alır, çözer ve orijinal dosyayı döner."""
        # İlk 16 byte IV'dir, kalanı veridir
        iv = encrypted_file_bytes[:16]
        actual_data = encrypted_file_bytes[16:]
        
        cipher = Cipher(algorithms.AES(SecurityManager.STATIC_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(actual_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        original_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        return original_bytes

# --- VERİTABANI MODELLERİ ---
class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False) # Gerçek uygulamada hashlenmeli

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tc_no = db.Column(db.String(11), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False) # Gerçek uygulamada hashlenmeli

class LabReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(100), nullable=False)
    tc_no = db.Column(db.String(11), nullable=False) # Patient tablosuyla ilişkilendirilebilir ama basitlik için böyle kalsın
    encrypted_content = db.Column(db.Text, nullable=False)
    # YENİ: Dosya yolu sütunu
    attachment_path = db.Column(db.String(200), nullable=True) 
    
    backup_encrypted_content = db.Column(db.Text, nullable=True) 
    iv = db.Column(db.String(50), nullable=False)
    data_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50))
    description = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)

def add_log(action, desc):
    log = SystemLog(action_type=action, description=desc)
    db.session.add(log)
    db.session.commit()

# --- ROTALAR ---

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'doctor':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if Doctor.query.filter_by(username=username).first():
                flash('Bu kullanıcı adı zaten alınmış.', 'danger')
                return redirect(url_for('register'))
                
            new_doctor = Doctor(username=username, password=password)
            db.session.add(new_doctor)
            db.session.commit()
            add_log('Kayıt', f'Yeni doktor kaydı: {username}')
            flash('Doktor kaydı başarılı! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login_page'))
            
        elif role == 'patient':
            name = request.form.get('name')
            tc_no = request.form.get('tc_no')
            password = request.form.get('password')
            
            if Patient.query.filter_by(tc_no=tc_no).first():
                flash('Bu TC Kimlik No ile zaten kayıt var.', 'danger')
                return redirect(url_for('register'))
                
            new_patient = Patient(name=name, tc_no=tc_no, password=password)
            db.session.add(new_patient)
            db.session.commit()
            add_log('Kayıt', f'Yeni hasta kaydı: {name}')
            flash('Hasta kaydı başarılı! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login_page'))
            
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    role = request.form.get('role')
    
    if role == 'doctor':
        username = request.form.get('username')
        password = request.form.get('password')
        
        doctor = Doctor.query.filter_by(username=username, password=password).first()
        
        if doctor:
            session['user_role'] = 'doctor'
            session['username'] = doctor.username
            add_log('Giriş', f'Doktor {doctor.username} sisteme giriş yaptı.')
            return redirect(url_for('doctor_dashboard'))
            
    elif role == 'patient':
        tc_no = request.form.get('tc_no')
        password = request.form.get('password')
        
        patient = Patient.query.filter_by(tc_no=tc_no, password=password).first()
        
        if patient:
            session['user_role'] = 'patient'
            session['tc_no'] = patient.tc_no
            session['patient_name'] = patient.name
            add_log('Giriş', f'Hasta {patient.name} sisteme giriş yaptı.')
            # Hastanın raporlarını listelemesi için bir dashboard'a veya direkt rapora yönlendirebiliriz
            # Şimdilik ilk raporuna yönlendirelim veya bir hasta paneli yapalım.
            # Mevcut yapıda view_report var.
            report = LabReport.query.filter_by(tc_no=tc_no).first()
            if report:
                return redirect(url_for('view_report', id=report.id))
            else:
                flash('Henüz adınıza kayıtlı bir rapor bulunmamaktadır.', 'warning')
                return redirect(url_for('login_page'))
                
    flash('Giriş başarısız! Kullanıcı adı/TC veya şifre hatalı.', 'danger')
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.pop('user_role', None)
    return redirect(url_for('login_page'))

@app.route('/doctor/dashboard')
def doctor_dashboard():
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
    reports = LabReport.query.order_by(LabReport.created_at.desc()).all()
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(15).all()
    return render_template('doctor_dashboard.html', reports=reports, logs=logs)

# --- YENİ DOSYA EKLEME KISMI ---
@app.route('/doctor/add', methods=['GET', 'POST'])
def add_report():
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
        
    if request.method == 'POST':
        p_name = request.form['patient_name']
        tc_no = request.form['tc_no']
        raw_result = request.form['lab_result']
        
        # Hasta Kontrolü / Oluşturma
        patient = Patient.query.filter_by(tc_no=tc_no).first()
        if not patient:
            # Yeni hasta ise şifresini de al
            p_password = request.form.get('patient_password')
            if not p_password:
                flash('Yeni hasta için şifre girilmesi zorunludur!', 'danger')
                return redirect(url_for('add_report'))
            
            new_patient = Patient(tc_no=tc_no, name=p_name, password=p_password)
            db.session.add(new_patient)
            db.session.commit()
            add_log('Kayıt', f'Yeni hasta kaydı oluşturuldu: {p_name}')
        
        # 1. Metni Şifrele
        secure_blob = SecurityManager.encrypt(raw_result)

        # 2. Dosya Varsa Al ve Şifrele
        file = request.files['file'] # HTML formundan gelen dosya
        saved_filename = None
        
        if file and file.filename != '':
            # Dosya adını güvenli hale getir ve uzantısına .enc ekle
            original_filename = file.filename
            saved_filename = f"{datetime.datetime.now().timestamp()}_{original_filename}.enc"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            
            # Dosyayı byte olarak oku
            file_bytes = file.read()
            # Şifrele
            encrypted_bytes = SecurityManager.encrypt_file_bytes(file_bytes)
            
            # Şifreli halini diske yaz
            with open(file_path, 'wb') as f:
                f.write(encrypted_bytes)

        new_report = LabReport(
            patient_name=p_name,
            tc_no=tc_no,
            encrypted_content=secure_blob['enc_data'],
            iv=secure_blob['iv'],
            data_hash=secure_blob['hash'],
            attachment_path=saved_filename # Dosya adını veritabanına kaydet
        )
        db.session.add(new_report)
        add_log('Ekleme', f'{p_name} için dosya ekli rapor oluşturuldu.')
        db.session.commit()
        
        flash('Rapor ve dosya şifrelenerek kaydedildi.', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    return render_template('add.html')

# --- YENİ: DOSYA İNDİRME ROTASI ---
@app.route('/download/<int:id>')
def download_file(id):
    report = LabReport.query.get_or_404(id)
    
    if not report.attachment_path:
        flash('Bu raporda dosya yok.', 'warning')
        return redirect(url_for('view_report', id=id))

    try:
        # 1. Şifreli dosyayı diskten oku
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], report.attachment_path)
        with open(file_path, 'rb') as f:
            encrypted_bytes = f.read()
            
        # 2. Şifreyi Çöz
        decrypted_bytes = SecurityManager.decrypt_file_bytes(encrypted_bytes)
        
        # 3. Kullanıcıya gönder (Orijinal ismini tahmin ederek)
        # Dosya adı "TIMESTAMP_isim.pdf.enc" şeklindeydi. Sondaki .enc'yi atıyoruz.
        download_name = report.attachment_path.replace('.enc', '').split('_', 1)[1]
        
        return send_file(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            download_name=download_name
        )
    except Exception as e:
        flash(f'Dosya indirme hatası: {str(e)}', 'danger')
        return redirect(url_for('view_report', id=id))

# (Diğer rotalar: tamper, restore, delete, view aynı kalacak...)
@app.route('/tamper/<int:id>')
def tamper_data(id):
    # (Eski kodun aynısı)
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
    report = LabReport.query.get_or_404(id)
    if not report.backup_encrypted_content: report.backup_encrypted_content = report.encrypted_content
    original = report.encrypted_content
    report.encrypted_content = original[:-1] + ('X' if original[-1] != 'X' else 'Y')
    add_log('SALDIRI SİMÜLASYONU', f'{report.patient_name} verisi bozuldu!')
    db.session.commit()
    flash('Veri HACKLENDİ!', 'danger')
    return redirect(url_for('doctor_dashboard'))

@app.route('/restore/<int:id>')
def restore_data(id):
    # (Eski kodun aynısı)
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
    report = LabReport.query.get_or_404(id)
    if report.backup_encrypted_content:
        report.encrypted_content = report.backup_encrypted_content
        report.backup_encrypted_content = None
        add_log('Kurtarma', f'{report.patient_name} verisi kurtarıldı.')
        db.session.commit()
        flash('Veri kurtarıldı.', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/delete/<int:id>')
def delete_report(id):
    # (Eski kodun aynısı)
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
    report = LabReport.query.get_or_404(id)
    # Varsa dosyasını da sil
    if report.attachment_path:
        try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], report.attachment_path))
        except: pass
    db.session.delete(report)
    add_log('Silme', 'Rapor silindi.')
    db.session.commit()
    flash('Kayıt silindi.', 'info')
    return redirect(url_for('doctor_dashboard'))
    
@app.route('/doctor/edit/<int:id>', methods=['GET', 'POST'])
def edit_report(id):
    # (Eski kodun aynısı - Dosya güncelleme eklemedik basit kalsın diye)
    if session.get('user_role') != 'doctor': return redirect(url_for('login_page'))
    report = LabReport.query.get_or_404(id)
    if request.method == 'POST':
        p = request.form['patient_name']
        t = request.form['tc_no']
        r = request.form['lab_result']
        s = SecurityManager.encrypt(r)
        report.patient_name = p
        report.tc_no = t
        report.encrypted_content = s['enc_data']
        report.iv = s['iv']
        report.data_hash = s['hash']
        report.backup_encrypted_content = None
        add_log('Güncelleme', 'Veri güncellendi.')
        db.session.commit()
        return redirect(url_for('doctor_dashboard'))
    v, c = SecurityManager.decrypt(report.encrypted_content, report.iv, report.data_hash)
    return render_template('edit.html', report=report, content=c)

@app.route('/view/<int:id>')
def view_report(id):
    report = LabReport.query.get_or_404(id)
    if session.get('user_role') == 'doctor':
         add_log('Görüntüleme', f'Doktor, {report.patient_name} raporunu görüntüledi.')
    is_valid, content = SecurityManager.decrypt(report.encrypted_content, report.iv, report.data_hash)
    return render_template('view.html', report=report, content=content, is_valid=is_valid)

if __name__ == '__main__':
    with app.app_context():
        # Tabloları sıfırla (Yeni modeller eklendiği için)
        # db.drop_all() # <-- İlk çalıştırmada bunu açın, sonra kapatın
        db.create_all()
        
        # Varsayılan Doktor Ekle (Eğer yoksa)
        if not Doctor.query.filter_by(username='admin').first():
            default_doctor = Doctor(username='admin', password='admin')
            db.session.add(default_doctor)
            db.session.commit()
            print("Varsayılan doktor (admin/admin) oluşturuldu.")
            
    app.run(debug=True)