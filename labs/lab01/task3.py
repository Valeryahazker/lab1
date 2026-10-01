"""Завдання 3: хешування, CSV-база та JSON-журнал з винятками."""

import csv
import functools
import hashlib
import hmac
import inspect
import json
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

from labs.lab01.variants import LAB_VARIANT, TASK3_VARIANTS
from shared.student import VARIANT_NUMBER

HASH_ALGORITHM, MIN_PASSWORD_LENGTH = TASK3_VARIANTS[LAB_VARIANT]
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_CSV = DATA_DIR / "users.csv"
LOG_JSON = DATA_DIR / "log.json"
CSV_HEADER = ("username", "password_hash")

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
SENSITIVE_PARAMETERS = frozenset({"password"})
MASK = "***"

# База користувачів у пам'яті: список пар (логін, хеш пароля).
users_db: list[tuple[str, str]] = []


class ValidationError(Exception):
    """Пароль коротший за мінімальну довжину з варіанту."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повернути hex-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль має містити щонайменше {MIN_PASSWORD_LENGTH} символів"
        )
    data = (password + salt).encode("utf-8")
    return hashlib.new(HASH_ALGORITHM, data).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Повернути запис користувача: (логін, хеш пароля з сіллю)."""
    if not username:
        raise ValueError("Логін не може бути порожнім")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list: Iterable[tuple[str, str]]) -> int:
    """Зареєструвати користувачів і записати базу в users.csv.

    Некоректний запис пропускається з повідомленням, щоб одна
    помилка не зупиняла реєстрацію решти користувачів.
    """
    records = []
    for username, password in users_list:
        try:
            records.append(create_user(username, password))
        except (ValueError, ValidationError) as error:
            print(f"  [!] {username!r} пропущено: {error}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with USERS_CSV.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(CSV_HEADER)
        writer.writerows(records)
    return len(records)


def load_users_db() -> list[tuple[str, str]]:
    """Зчитати users.csv у список users_db."""
    with USERS_CSV.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        records = [(row["username"], row["password_hash"]) for row in reader]
    users_db.clear()
    users_db.extend(records)
    return users_db


def print_users_db(records: list[tuple[str, str]]) -> None:
    """Вивести базу користувачів у вигляді таблиці."""
    width = max([len("Логін")] + [len(name) for name, _ in records])
    print(f"{'№':>2}  {'Логін':<{width}}  Хеш пароля ({HASH_ALGORITHM})")
    for number, (username, password_hash) in enumerate(records, 1):
        print(f"{number:>2}  {username:<{width}}  {password_hash}")


def _read_log_entries() -> list:
    """Прочитати журнал; пошкоджений файл зберегти як .bak."""
    if not LOG_JSON.exists():
        return []
    try:
        with LOG_JSON.open(encoding="utf-8") as file:
            entries = json.load(file)
    except json.JSONDecodeError:
        entries = None
    if isinstance(entries, list):
        return entries
    # Журнал аудиту не видаляємо: зберігаємо копію для розбору.
    LOG_JSON.replace(LOG_JSON.with_name(LOG_JSON.name + ".bak"))
    return []


def _append_log_entry(entry: dict) -> None:
    """Дописати подію в JSON-журнал (масив об'єктів)."""
    entries = _read_log_entries()
    entries.append(entry)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_JSON.open("w", encoding="utf-8") as file:
        json.dump(entries, file, ensure_ascii=False, indent=4, default=str)


def _mask_arguments(
    func: Callable[..., bool], args: tuple, kwargs: dict
) -> tuple[list, dict]:
    """Замінити значення чутливих параметрів (пароля) на маску."""
    names = list(inspect.signature(func).parameters)
    safe_args = [
        MASK if name in SENSITIVE_PARAMETERS else value
        for name, value in zip(names, args)
    ]
    safe_kwargs = {
        key: MASK if key in SENSITIVE_PARAMETERS else value
        for key, value in kwargs.items()
    }
    return safe_args, safe_kwargs


def log_event(func: Callable[..., bool]) -> Callable[..., bool]:
    """Записувати кожен виклик функції (спробу входу) у log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        success = False
        try:
            success = bool(func(*args, **kwargs))
        finally:
            # Виконується і при успіху, і при винятку всередині func.
            safe_args, safe_kwargs = _mask_arguments(func, args, kwargs)
            _append_log_entry(
                {
                    "event": func.__name__,
                    "user": kwargs.get("username", args[0] if args else ""),
                    "result": "success" if success else "failure",
                    "timestamp": datetime.now().strftime(TIMESTAMP_FORMAT),
                    "args": safe_args,
                    "kwargs": safe_kwargs,
                }
            )
        return success

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Автентифікувати користувача за логіном і паролем."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    stored_hash = dict(users_db).get(username)
    if stored_hash is None:
        return False
    try:
        password_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False  # закороткий пароль не може бути правильним
    return hmac.compare_digest(password_hash, stored_hash)


def demo_hashing() -> None:
    """Показати вплив солі та реакцію generate_hash на помилки."""
    sample = "Lviv#Polytech2026"
    default_hash = generate_hash(sample)
    personal_hash = generate_hash(sample, PERSONAL_SALT)
    print(f"  '{sample}' + сіль 00000: {default_hash[:40]}...")
    print(f"  '{sample}' + сіль {PERSONAL_SALT}: {personal_hash[:40]}...")
    print(
        f"  Довжина хешу {HASH_ALGORITHM}: {len(personal_hash)} hex-символів"
    )
    bad_inputs = (
        ("", PERSONAL_SALT),
        ("Short#1", PERSONAL_SALT),
        (sample, ""),
    )
    for password, salt in bad_inputs:
        call = f"generate_hash({password!r}, {salt!r})"
        try:
            generate_hash(password, salt)
        except ValidationError as error:
            print(f"  {call} -> ValidationError: {error}")
        except ValueError as error:
            print(f"  {call} -> ValueError: {error}")


def demo_logins() -> None:
    """Виконати кілька спроб входу; кожна потрапляє в log.json."""
    attempts = (
        ("andrii", "Lviv#Polytech2026", "правильний пароль"),
        ("olena", "Kvitka!Sonyashnyk8", "неправильний пароль"),
        ("hacker", "Lviv#Polytech2026", "неіснуючий користувач"),
        ("taras", "short", "закороткий пароль"),
        ("", "Lviv#Polytech2026", "порожній логін"),
    )
    for username, password, note in attempts:
        try:
            result = "success" if login(username, password) else "failure"
            print(f"  {note:<22} login({username!r}) -> {result}")
        except ValueError as error:
            print(f"  {note:<22} login({username!r}) -> ValueError: {error}")
    # Виклик з іменованими аргументами: у журналі заповниться kwargs.
    ok = login(username="iryna", password="Karpaty@Hoverla2061")
    note = "виклик через kwargs"
    print(f"  {note:<22} login('iryna') -> {'success' if ok else 'failure'}")


def _show(path: Path) -> str:
    """Шлях відносно кореня репозиторію для виводу на екран."""
    return path.relative_to(PROJECT_ROOT).as_posix()


def main() -> None:
    """Запустити всі кроки завдання 3 з обробкою винятків."""
    print(
        f"Алгоритм: {HASH_ALGORITHM}; мінімальна довжина пароля: "
        f"{MIN_PASSWORD_LENGTH}; персональна сіль: {PERSONAL_SALT}"
    )
    # Тестові облікові записи (логін, пароль) для реєстрації.
    users_to_register = (
        ("andrii", "Lviv#Polytech2026"),
        ("olena", "Kvitka!Sonyashnyk7"),
        ("taras", "Kobzar_Shevchenko1814"),
        ("iryna", "Karpaty@Hoverla2061"),
        ("bohdan", "Dnipro$River2026ua"),
        ("sofiia", "Chervona#Kalyna22"),
        ("maksym", "Borshch&Pampushky9"),
        ("oksana", "Vyshyvanka*Rodovid5"),
        ("dmytro", "Kozak!Mamai1648xy"),
        ("kateryna", "Tryzub=Volia2026!"),
    )
    try:
        print("\n1) generate_hash: вплив солі та обробка помилок")
        demo_hashing()

        print("\n2) Реєстрація користувачів")
        count = create_users(users_to_register)
        print(f"  Записано {count} користувачів у {_show(USERS_CSV)}")

        print("\n3) Вміст бази users_db")
        print_users_db(load_users_db())

        print("\n4) Спроби входу")
        demo_logins()

        print(f"\n5) Останній запис журналу {_show(LOG_JSON)}")
        print(
            json.dumps(_read_log_entries()[-1], ensure_ascii=False, indent=4)
        )
    except FileNotFoundError as error:
        print(f"[Помилка] Файл не знайдено: {error.filename}")
    except PermissionError as error:
        print(f"[Помилка] Немає прав доступу до файлу: {error.filename}")
    except IOError as error:
        print(f"[Помилка] Помилка вводу-виводу: {error}")
    except ValidationError as error:
        print(f"[Помилка валідації] {error}")
    except ValueError as error:
        print(f"[Помилка] Некоректні дані: {error}")


if __name__ == "__main__":
    main()
