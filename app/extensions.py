# [HARDENING] wspolne instancje rozszerzen bezpieczenstwa (inicjalizowane w create_app).
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

login_manager = LoginManager()   # [HARDENING A07] solidne zarzadzanie sesja
csrf = CSRFProtect()             # [HARDENING A01/CSRF] ochrona anty-CSRF dla formularzy
limiter = Limiter(key_func=get_remote_address)  # [HARDENING A06/A07] rate limiting
