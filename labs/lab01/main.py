"""Головний файл: демонстрація всіх завдань лабораторної роботи №1.

Запуск з кореня репозиторію:
    python -m labs.lab01.main
"""

from labs.lab01 import task1, task2, task3

LINE = "=" * 72


def print_section(title: str) -> None:
    """Вивести заголовок розділу."""
    print(f"\n{LINE}\n{title}\n{LINE}")


def main() -> None:
    """Послідовно запустити всі три завдання."""
    print("Лабораторна робота №1: основи Python, Git та стиль коду")
    sections = (
        ("Завдання 1. Аналізатор надійності паролів", task1.main),
        ("Завдання 2. Система контролю доступу", task2.main),
        ("Завдання 3. Хешування, CSV-база та JSON-журнал", task3.main),
    )
    for title, run in sections:
        print_section(title)
        run()


if __name__ == "__main__":
    main()
