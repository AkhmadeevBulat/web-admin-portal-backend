import asyncio
from ldap3 import Server, ALL, Connection
import importlib  # Для динамической загрузки config
from collections import defaultdict  # Для JSON
import config


# Асинхронная функция для запроса данных из LDAP
async def read_ldap_data():
    def _load_users_from_ldap():
        new_data_users = defaultdict(lambda: defaultdict(dict))
        importlib.reload(config)
        try:
            server = Server(config.LDAP_SERVER, get_info=ALL)
            conn = Connection(server, user=config.LDAP_USER, password=config.LDAP_PASSWORD, auto_bind=True)
            for base in config.SEARCH_USERS:
                conn.search(
                    search_base=base,
                    search_filter="(objectClass=person)",
                    attributes=[
                        "cn",
                        "distinguishedName",
                        "sAMAccountName",
                        "userPrincipalName",
                        "givenName",
                        "sn",
                        "middleName",
                        "company",
                        "department",
                        "telephoneNumber",
                        "title",
                        "mail",
                        "description",
                        "manager",
                        "physicalDeliveryOfficeName",
                        "description",
                        "displayName",
                        "initials",
                        "lastLogon",
                        "lastLogonTimestamp",
                        "logonCount",
                        "name",
                        "whenCreated"
                    ]
                )
                for entry in conn.entries:
                    cn = str(entry.cn)
                    user_info = {attr: str(entry[attr]) for attr in entry.entry_attributes}
                    new_data_users[cn] = user_info
        except Exception:
            pass
        return new_data_users


    def _load_groups_from_ldap():
        new_data_groups = defaultdict(lambda: defaultdict(dict))
        importlib.reload(config)
        try:
            server = Server(config.LDAP_SERVER, get_info=ALL)
            conn = Connection(server, user=config.LDAP_USER, password=config.LDAP_PASSWORD, auto_bind=True)
            for base in config.SEARCH_GROUPS:
                conn.search(
                    search_base=base,
                    search_filter="(objectClass=group)",
                    attributes=[
                        "cn",
                        "distinguishedName",
                        "member",
                        "name",
                        "sAMAccountName"
                    ]
                )
                for entry in conn.entries:
                    cn = str(entry.cn)
                    group_info = {attr: str(entry[attr]) for attr in entry.entry_attributes}
                    new_data_groups[cn] = group_info
        except Exception:
            pass
        return new_data_groups


    def _load_ou_from_ldap():  # Добавить функционал выведения OU
        new_data_ou = defaultdict(lambda: defaultdict(dict))
        importlib.reload(config)
        try:
            server = Server(config.LDAP_SERVER, get_info=ALL)
            conn = Connection(server, user=config.LDAP_USER, password=config.LDAP_PASSWORD, auto_bind=True)
            for base in config.SEARCH_OU:
                conn.search(
                    search_base=base,
                    search_filter="(objectClass=organizationalUnit)",  # Надо понять как выводить помимо OU еще и контейнеры, а также как выводить в JSON в виде дерева
                    attributes=[
                        "ou"
                        "distinguishedName",
                        "name",
                    ]
                )
                for entry in conn.entries:
                    name = str(entry.name)
                    ou_info = {attr: str(entry[attr]) for attr in entry.entry_attributes}
                    new_data_ou[name] = ou_info
        except Exception:
            pass
        return new_data_ou

    loop = asyncio.get_running_loop()
    new_data_users = await loop.run_in_executor(None, _load_users_from_ldap)
    new_data_groups = await loop.run_in_executor(None, _load_groups_from_ldap)
    new_data_ou = await loop.run_in_executor(None, _load_ou_from_ldap)

    return new_data_users, new_data_groups, new_data_ou