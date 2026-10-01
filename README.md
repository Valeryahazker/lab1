# cybersecurity-python-labs

Лабораторні роботи з Python на тематику кібербезпеки.
Студент: Савченко Андрій, група КБ-208.

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m labs.lab01.main        # усі завдання ЛР №1
python -m labs.lab01.task3       # окреме завдання
```

Команди запускаються з кореня репозиторію: так Python бачить пакети
`labs` і `shared` без правки `sys.path`.

## Перевірка стилю (Ruff)

```bash
ruff check .           # лінтер
ruff check --fix .     # автовиправлення
ruff format .          # форматування
```

Налаштування лінтера в `ruff.toml` (PEP-8: 79 символів у рядку,
72 для docstring і коментарів).

## Структура

```
shared/student.py        дані студента (ПІБ, група, варіант)
labs/lab01/variants.py   вхідні дані варіантів 1-15
labs/lab01/task1.py      аналізатор надійності паролів
labs/lab01/task2.py      система контролю доступу
labs/lab01/task3.py      хешування, CSV-база, JSON-журнал
labs/lab01/main.py       запуск усіх завдань
labs/lab01/data/         users.csv і log.json (створюються під час
                         запуску, у git не потрапляють)
```
