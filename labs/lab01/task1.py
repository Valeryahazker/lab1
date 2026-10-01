"""Завдання 1: комплексний аналізатор надійності паролів."""

import random
import string
from collections import Counter

from labs.lab01.variants import LAB_VARIANT, TASK1_VARIANTS
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DUPLICATES_COUNT = 3
VERY_STRONG_EXTRA_LENGTH = 4
SPECIAL_CHARACTERS = frozenset(string.punctuation)

FORBIDDEN = "Заборонений"
WEAK = "Слабкий"
MEDIUM = "Середній"
STRONG = "Сильний"
VERY_STRONG = "Дуже сильний"
RATINGS_ORDER = (FORBIDDEN, WEAK, MEDIUM, STRONG, VERY_STRONG)

# Позначення груп символів у колонці "Склад" таблиці результатів.
GROUP_SYMBOLS = {"lower": "a", "upper": "A", "digit": "1", "special": "@"}

# Паролі не з варіанту: показують гілки "Слабкий" і "Середній",
# якщо серед даних варіанту таких паролів немає.
EXTRA_EXAMPLES = (
    "1234567890123",
    "lowercaseonlypass",
    "summer2026lviv",
    "Summer2026Lviv",
)


def add_random_duplicates(
    passwords: list[str], count: int = DUPLICATES_COUNT
) -> tuple[list[str], list[int]]:
    """Дописати в кінець копії списку дублікати випадкових паролів.

    Імітує повторне використання паролів. Повертає новий список
    і вибрані індекси; вихідний список не змінюється.
    """
    indices = random.sample(range(len(passwords)), count)
    extended = list(passwords)
    extended.extend(passwords[index] for index in indices)
    return extended, indices


def get_character_groups(password: str) -> dict[str, bool]:
    """Визначити, які групи символів є в паролі."""
    return {
        "lower": any(char.islower() for char in password),
        "upper": any(char.isupper() for char in password),
        "digit": any(char.isdigit() for char in password),
        "special": any(char in SPECIAL_CHARACTERS for char in password),
    }


def meets_all_criteria(groups: dict[str, bool], criteria: dict) -> bool:
    """Перевірити обов'язкові вимоги до складу пароля."""
    required = {
        "digit": criteria.get("require_digits", False),
        "upper": criteria.get("require_upper", False),
        "special": criteria.get("require_special", False),
    }
    return all(groups[name] for name, needed in required.items() if needed)


def evaluate_password(
    password: str, occurrences: int, criteria: dict, forbidden: set[str]
) -> str:
    """Оцінити надійність пароля за алгоритмом із завдання."""
    min_length = criteria["min_length"]
    if password in forbidden or len(password) < min_length:
        return FORBIDDEN
    groups = get_character_groups(password)
    if meets_all_criteria(groups, criteria):
        is_long = len(password) >= min_length + VERY_STRONG_EXTRA_LENGTH
        if is_long and occurrences == 1:
            return VERY_STRONG
        return STRONG
    if sum(groups.values()) >= 2:
        return MEDIUM
    return WEAK


def analyze_passwords(
    passwords: list[str], criteria: dict, forbidden: set[str]
) -> list[tuple[str, int, str]]:
    """Оцінити кожен пароль списку з урахуванням його повторів."""
    occurrences = Counter(passwords)
    results = []
    for password in passwords:
        count = occurrences[password]
        rating = evaluate_password(password, count, criteria, forbidden)
        results.append((password, count, rating))
    return results


def describe_groups(password: str) -> str:
    """Показати склад пароля, наприклад "aA1@" або "a-1-"."""
    groups = get_character_groups(password)
    return "".join(
        symbol if groups[name] else "-"
        for name, symbol in GROUP_SYMBOLS.items()
    )


def print_results(results: list[tuple[str, int, str]]) -> None:
    """Вивести результати аналізу у вигляді таблиці."""
    width = max([len("Пароль")] + [len(item[0]) for item in results])
    header = (
        f"{'№':>2}  {'Пароль':<{width}}  {'Довж.':>5}  {'Склад':<5}  "
        f"{'Повт.':>5}  Оцінка"
    )
    rows = [
        f"{number:>2}  {password:<{width}}  {len(password):>5}  "
        f"{describe_groups(password):<5}  {count:>5}  {rating}"
        for number, (password, count, rating) in enumerate(results, 1)
    ]
    rule = "-" * max(len(line) for line in [header, *rows])
    print(header)
    print(rule)
    print("\n".join(rows))
    print(rule)


def print_summary(results: list[tuple[str, int, str]]) -> None:
    """Вивести кількість паролів у кожній категорії."""
    counts = Counter(rating for _, _, rating in results)
    summary = ", ".join(f"{name}: {counts[name]}" for name in RATINGS_ORDER)
    print(f"Підсумок: {summary}")


def main() -> None:
    """Запустити аналіз паролів для варіанту студента."""
    data = TASK1_VARIANTS[LAB_VARIANT]
    criteria = data["criteria"]
    forbidden = data["forbidden_passwords"]
    min_length = criteria["min_length"]

    print(
        f"Студент: {STUDENT_NAME} ({GROUP_NAME}), варіант {VARIANT_NUMBER}"
        f" -> дані варіанту {LAB_VARIANT}"
    )
    print(
        f"Мінімальна довжина: {min_length}; для оцінки 'Дуже сильний': "
        f"{min_length + VERY_STRONG_EXTRA_LENGTH}+ символів і унікальність"
    )

    passwords, indices = add_random_duplicates(data["passwords"])
    duplicated = ", ".join(data["passwords"][index] for index in indices)
    print(f"Продубльовано паролі з індексами {indices}: {duplicated}\n")

    results = analyze_passwords(passwords, criteria, forbidden)
    print_results(results)
    print_summary(results)

    print("\nДодаткові приклади (не з варіанту) для решти гілок алгоритму:")
    print_results(analyze_passwords(list(EXTRA_EXAMPLES), criteria, forbidden))
    print("Склад: a - малі літери, A - великі, 1 - цифри, @ - спецсимволи")


if __name__ == "__main__":
    main()
