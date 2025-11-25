# Common Mistakes and Anti-Patterns

This file contains detailed anti-patterns and common security mistakes referenced from main SKILL.md Section 8.

---

## Mistake 1: Trusting Client-Side Validation

```javascript
// ❌ NEVER rely solely on client-side validation
function submitForm() {
  const age = document.getElementById('age').value;
  if (age < 18) {
    alert('Must be 18+');
    return; // Attacker can bypass with DevTools
  }
  fetch('/api/register', {method: 'POST', body: JSON.stringify({age})});
}

// ✅ ALWAYS validate on server
@app.route('/api/register', methods=['POST'])
def register():
    age = request.json.get('age')

    # Server-side validation
    if not isinstance(age, int) or age < 18:
        return jsonify({'error': 'Must be 18+'}), 400

    # Proceed with registration
```

---

## Mistake 2: Using Blacklists Instead of Allowlists

```python
# ❌ BAD: Blacklist (incomplete)
def validate_filename_bad(filename):
    blocked = ['.exe', '.sh', '.bat']
    return not any(filename.endswith(ext) for ext in blocked)
    # Attacker can use: .php, .jsp, .aspx, etc.

# ✅ GOOD: Allowlist (secure)
def validate_filename_good(filename):
    allowed = ['.jpg', '.png', '.pdf', '.txt']
    return any(filename.lower().endswith(ext) for ext in allowed)
```

---

## Mistake 3: Exposing Sensitive Information in Errors

```python
# ❌ BAD: Exposes database structure
except SQLAlchemyError as e:
    return jsonify({'error': str(e)}), 500
    # Returns: "Column 'password_hash' does not exist"

# ✅ GOOD: Generic error message
except SQLAlchemyError as e:
    app.logger.error(f"Database error: {str(e)}", exc_info=True)
    return jsonify({'error': 'An error occurred'}), 500
```

---

## Mistake 4: Insecure Randomness

```python
# ❌ BAD: Predictable random
import random
reset_token = ''.join(random.choices('0123456789', k=6))  # Predictable!

# ✅ GOOD: Cryptographically secure
import secrets
reset_token = secrets.token_urlsafe(32)  # Secure random
```

---

## Mistake 5: Mass Assignment Vulnerabilities

```python
# ❌ VULNERABLE: Mass assignment
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)

    # Directly update from request - attacker can set is_admin=True!
    for key, value in request.json.items():
        setattr(user, key, value)

    db.session.commit()

# ✅ SECURE: Explicit field assignment
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user_secure(user_id):
    user = User.query.get_or_404(user_id)

    # Only allow specific fields
    allowed_fields = ['email', 'display_name', 'bio']

    for field in allowed_fields:
        if field in request.json:
            setattr(user, field, request.json[field])

    db.session.commit()
```

---

## Mistake 6: Insecure File Uploads

```python
# ❌ VULNERABLE: File upload without validation
@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # Path traversal!

# ✅ SECURE: File upload with validation
import os
from werkzeug.utils import secure_filename

@app.route('/api/upload', methods=['POST'])
def upload_file_secure():
    file = request.files.get('file')

    if not file:
        return jsonify({'error': 'No file provided'}), 400

    # Validate file extension
    allowed_extensions = {'.jpg', '.png', '.pdf'}
    ext = os.path.splitext(file.filename)[1].lower()

    if ext not in allowed_extensions:
        return jsonify({'error': 'File type not allowed'}), 400

    # Validate file size (10MB max)
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > 10 * 1024 * 1024:
        return jsonify({'error': 'File too large'}), 400

    # Secure filename
    filename = secure_filename(file.filename)

    # Generate unique filename
    unique_filename = f"{secrets.token_hex(16)}_{filename}"

    # Save outside web root
    upload_path = os.path.join('/var/uploads', unique_filename)
    file.save(upload_path)

    return jsonify({'filename': unique_filename})
```

---

## Mistake 7: Hardcoded Credentials

```python
# ❌ NEVER DO THIS
DATABASE_URL = "postgresql://admin:SuperSecret123@db.example.com/mydb"
API_KEY = "sk_live_123456789abcdef"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ✅ ALWAYS use environment variables or secret managers
DATABASE_URL = os.getenv('DATABASE_URL')
API_KEY = vault.get_secret('myapp/api-keys', 'stripe')
```

---

## Mistake 8: Missing CSRF Protection

```html
<!-- ❌ VULNERABLE: No CSRF token -->
<form method="POST" action="/api/transfer">
  <input name="amount" value="1000">
  <input name="to_account" value="attacker_account">
  <button>Transfer</button>
</form>

<!-- ✅ SECURE: CSRF token -->
<form method="POST" action="/api/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="amount" value="1000">
  <input name="to_account" value="12345">
  <button>Transfer</button>
</form>
```

---

## Mistake 9: Weak Password Hashing

```python
# ❌ NEVER DO THIS
import hashlib

def bad_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # INSECURE!
    return hashlib.sha1(password.encode()).hexdigest()  # INSECURE!
    return hashlib.sha256(password.encode()).hexdigest()  # NO SALT!

# ✅ ALWAYS use Argon2id or bcrypt
from argon2 import PasswordHasher

ph = PasswordHasher()
password_hash = ph.hash("user_password")
is_valid = ph.verify(password_hash, "user_password")
```

---

## Mistake 10: Logging Sensitive Data

```python
# ❌ BAD: Logging passwords, tokens, PII
logger.info(f"User login: {username}, password: {password}")  # NEVER!
logger.info(f"API request with token: {auth_token}")  # NEVER!
logger.info(f"User email: {user.email}, SSN: {user.ssn}")  # NEVER!

# ✅ GOOD: Log only safe context
logger.info(f"User login attempt", extra={
    'user_id': hash_id(user.id),  # Hash PII
    'ip_address': request.remote_addr,
    'success': True
})
# Never log: passwords, tokens, API keys, SSNs, credit cards
```
