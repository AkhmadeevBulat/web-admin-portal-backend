import asyncio
from ldap3 import Server, ALL, Connection
import importlib  # Для динамической загрузки config
from collections import defaultdict  # Для JSON
import config


async def add_user_ad(
        last_name: str,  # Фамилия
        first_name: str,  # Имя
        middle_name: str,  # Отчество
        title: str,  # Должность
        company: str,  # Департамент
        department: str,  # Отдел
        physical_delivery_office_name: str,  # Кабинет
        work_phone: str,  # Рабочий телефон
        member_of: dict[str],  # Кортеж DN объектов групп политик
        password: str,  # Пароль
        change_pass_auth: bool,  # Смена пароля при авторизации
        manager: str,  # DN объекта менеджера
        sAMAccountName: str,  # Логин
        userPrincipalName: str,  # логин@домен
        mail: str,  # Почта
        description: str  # Описание
):
    full_name = f"{last_name} {first_name} {middle_name}"  # Полное имя




