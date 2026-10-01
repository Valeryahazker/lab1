"""Завдання 2: багаторівнева система контролю доступу."""

from labs.lab01.variants import LAB_VARIANT, TASK2_VARIANTS

ALLOW = "ALLOW"
DENY = "DENY"


def get_level_name(level: int, security_levels: tuple[str, ...]) -> str:
    """Замінити числовий рівень безпеки (1-4) його назвою."""
    if not 1 <= level <= len(security_levels):
        raise ValueError(f"Невідомий рівень безпеки: {level}")
    return security_levels[level - 1]


def print_resources(
    resources: list[tuple[str, int]], security_levels: tuple[str, ...]
) -> None:
    """Вивести ресурси з текстовими назвами рівнів безпеки."""
    width = max(len(name) for name, _ in resources)
    for name, level in resources:
        print(f"  {name:<{width}}  {get_level_name(level, security_levels)}")


def check_access(
    username: str,
    resource_level: int,
    users: dict[str, dict],
    blocked_users: set[str],
) -> tuple[str, str]:
    """Перевірити доступ користувача до ресурсу.

    Повертає пару (рішення, причина); для ALLOW причина порожня.
    Доступ дозволяється лише після проходження всіх перевірок,
    у будь-якому іншому випадку результат DENY (fail-secure).
    """
    user = users.get(username)
    if user is None:
        return DENY, "User not found"
    if username in blocked_users:
        return DENY, "User is blocked"
    if not user["active"]:
        return DENY, "Account inactive"
    if user["clearance"] >= resource_level:
        return ALLOW, ""
    return DENY, "Insufficient clearance"


def format_decision(
    username: str, resource: str, decision: str, reason: str
) -> str:
    """Сформувати рядок результату у форматі із завдання."""
    line = f"user={username} resource={resource} -> {decision}"
    return f"{line} ({reason})" if reason else line


def demo_inactive_branch(
    users: dict[str, dict], resources: list[tuple[str, int]]
) -> None:
    """Показати гілку «Account inactive» без урахування блокувань."""
    resource_name, level = resources[0]
    for username, info in users.items():
        if not info["active"]:
            decision, reason = check_access(username, level, users, set())
            print(format_decision(username, resource_name, decision, reason))


def main() -> None:
    """Запустити перевірку доступу для даних варіанту."""
    data = TASK2_VARIANTS[LAB_VARIANT]
    users = data["users"]
    resources = data["resources"]
    security_levels = data["security_levels"]
    blocked_users = data["blocked_users"]

    print("Ресурси системи та їхні рівні безпеки:")
    print_resources(resources, security_levels)

    # Перевіряємо зареєстрованих користувачів, а також логіни зі
    # списку блокувань, яких немає в системі ("User not found").
    usernames = list(users) + sorted(blocked_users.difference(users))
    print("\nПеревірка доступу:")
    for username in usernames:
        for resource_name, level in resources:
            decision, reason = check_access(
                username, level, users, blocked_users
            )
            print(format_decision(username, resource_name, decision, reason))
        print()

    print("Додатково: неактивний запис поза списком блокувань")
    demo_inactive_branch(users, resources)


if __name__ == "__main__":
    main()
