import logging
import json
from contextlib import asynccontextmanager
from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
import os
import asyncio
from ldap3 import Server, ALL, Connection, Tls
import ssl
from ldap3.core.exceptions import LDAPException
import importlib
from collections import defaultdict  # Для JSON
from apscheduler.schedulers.background import BackgroundScheduler  # Для планировщика обновления данных
from datetime import datetime, timedelta
from auth_utils import create_access_token, verify_token
from config import *
import config
from ldap_data_ad import read_ldap_data


tls_config = Tls(
    validate=ssl.CERT_REQUIRED,        # Обязательная проверка сертификата
    ca_certs_file=LDAP_CA_CERT,        # Наш сертификат/CA
    version=ssl.PROTOCOL_TLS_CLIENT     # TLS 1.2 или новее
)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Хранилище данных
ldap_data_users = defaultdict(lambda: defaultdict(dict))
ldap_data_groups = defaultdict(lambda: defaultdict(dict))
ldap_data_ou = defaultdict(lambda: defaultdict(dict))


async def update_ldap_data():
    users, groups, ou = await read_ldap_data()
    ldap_data_users.clear()
    ldap_data_users.update(users)
    ldap_data_groups.clear()
    ldap_data_groups.update(groups)
    ldap_data_ou.clear()
    ldap_data_ou.update(ou)


# Планировщик обновления данных
scheduler = BackgroundScheduler()
scheduler.add_job(lambda: asyncio.run(update_ldap_data()), "interval", minutes=5)

# Lifespan для управления жизненным циклом приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    users, groups, ou = await read_ldap_data()
    ldap_data_users.clear()
    ldap_data_users.update(users)
    ldap_data_groups.clear()
    ldap_data_groups.update(groups)
    ldap_data_ou.clear()
    ldap_data_ou.update(ou)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],  # Или укажи конкретные адреса, например: ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],  # Или ["POST", "GET", "OPTIONS"]
    allow_headers=["*"],  # Или ["Authorization", "Content-Type"]
)


@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    # Выполним синхронную LDAP-логику в отдельном потоке,
    # чтобы не блокировать asyncio event loop.
    def ldap_auth_flow(username: str, password: str):
        admin_conn = None
        user_conn = None
        try:
            admin_conn = Connection(
                Server(LDAP_SERVER, port=int(LDAP_PORT), use_ssl=True, tls=tls_config, get_info=ALL),
                user=LDAP_USER,
                password=LDAP_PASSWORD,
                auto_bind=True
            )

            # Выполняем поиск пользователя по sAMAccountName (или другому атрибуту)
            search_base = SEARCH_BASES[0] if isinstance(SEARCH_BASES, (list, tuple)) and SEARCH_BASES else None
            if not search_base:
                raise RuntimeError("SEARCH_BASES not configured")

            found = admin_conn.search(
                search_base=search_base,
                search_filter=f"(sAMAccountName={username})",
                attributes=["memberOf", "distinguishedName"]
            )

            # Проверяем результат поиска
            if not found or not admin_conn.entries:
                # Не найден пользователь
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            entry = admin_conn.entries[0]

            # Получаем DN пользователя (distinguishedName)
            distinguished_name = str(entry.distinguishedName)
            member_of = entry.memberOf if "memberOf" in entry else []

            # Проверка членства в группе Domain Admins
            domain_admin_dn = getattr(config, "DOMAIN_ADMIN_GROUP_DN", None)
            is_admin = False

            if domain_admin_dn:
                # 1️⃣ Попробуем прямой запрос к группе — ищем, есть ли пользователь в member
                admin_conn.search(
                    search_base=domain_admin_dn,
                    search_filter=f"(member={distinguished_name})",
                    attributes=["cn"]
                )
                if admin_conn.entries:
                    is_admin = True
                else:
                    # 2️⃣ fallback — проверяем memberOf у пользователя (как было раньше)
                    is_admin = any(domain_admin_dn.lower() in str(g).lower() for g in member_of)
            else:
                # 3️⃣ fallback по имени группы (на случай отсутствия DOMAIN_ADMIN_GROUP_DN)
                is_admin = any("CN=Domain Admins".lower() in str(g).lower() for g in member_of)

            if not is_admin:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Not a Domain Admin")

            # Теперь пробуем bind от имени пользователя с переданным паролем
            try:
                user_conn = Connection(
                    Server(LDAP_SERVER, port=int(LDAP_PORT), use_ssl=True, tls=tls_config, get_info=ALL),
                    user=distinguished_name,
                    password=password,
                    auto_bind=True
                )
            except LDAPException:
                # Неверный пароль или bind не удался
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # Успешный вход — возвращаем имя (можно использовать distinguished_name или username)
            return {"username": username, "dn": distinguished_name}

        finally:
            # Гарантированно разрываем соединения
            try:
                if admin_conn:
                    admin_conn.unbind()
            except Exception:
                pass
            try:
                if user_conn:
                    user_conn.unbind()
            except Exception:
                pass

    # Вызовем синхронную функцию в отдельном потоке
    try:
        auth_result = await asyncio.to_thread(ldap_auth_flow, username, password)
    except HTTPException as he:
        # Перепрокидываем ожидаемые HTTP-исключения (401/403)
        logger.info(f"Login failed for user [{username}]: {he.detail}")
        raise he
    except Exception as e:
        # Логируем неожиданную ошибку и возвращаем 500
        logger.exception(f"Unexpected error during LDAP login for user [{username}]")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    # Создаём access token — добавь нужные claims в create_access_token
    access_token = create_access_token(data={"sub": auth_result["username"]})
    logger.info(f"User [{username}] logged in via LDAP (dn={auth_result['dn']})")

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/validate")
async def protected_route(username: str = Depends(verify_token)):
    return {"message": f"Hello, {username}! This is protected data."}


# Выдать департаменты и отделы
@app.get("/api/get_company_and_department")
async def get_company_and_departments(username: str = Depends(verify_token)):
    return COMPANY_AND_DEPARTMENT_FILTERS


# Выдать всех пользователей
@app.get("/api/get_users")
async def get_users(username: str = Depends(verify_token)):
    return ldap_data_users


@app.get("/api/get_groups")
async def get_groups(username: str = Depends(verify_token)):
    return ldap_data_groups


@app.get("/api/refresh_ldap_data")
async def refresh_ldap_data(username: str = Depends(verify_token)):
    try:
        await update_ldap_data()
        return {"status": "OK", "detail": "LDAP data refreshed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to refresh LDAP data: {str(e)}")


@app.post("/api/add_user_AD")
async def add_user_AD(username: str = Depends(verify_token)):
    pass

