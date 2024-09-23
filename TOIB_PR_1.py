# Практическая работа №1 по дисциплине ТОИБ
import hashlib  # Импортируем библиотеку для хеширования
from tkinter import Tk, Label, Entry, Button, StringVar, Frame  # Импортируем нужные классы из tkinter

# Функция для получения SHA-256 хеша от строки пароля
def get_sha256_hash(password: str) -> str:
    sha256 = hashlib.sha256()  # Создание объекта хеширования SHA-256
    sha256.update(password.encode('utf-8'))  # Преобразование пароля в байтовый формат, что необходимо для процесса хеширования строки
    return sha256.hexdigest()  # Возвращение хэша в виде шестнадцатеречной строки

# Функция для отображения хеша пароля
def show_hash():
    password = entry.get()  # Получаем пароль из поля ввода
    if password:  # Проверяем, введен ли пароль
        hashed_password = get_sha256_hash(password)  # Получаем хэш пароля
        result_var.set(hashed_password)  # Устанавливаем хэш в поле результата
    else:
        result_var.set("Пароль не был введен")  # Сообщаем об отсутствии пароля

# Функция для переключения видимости введенного пароля
def password_visibility():
    if entry.cget('show') == '*':  # Если пароль спрятан
        entry.config(show='')  # Показываем пароль
        toggle_button.config(text='Скрыть')  # Меняем текст кнопки на "Скрыть"
    else:
        entry.config(show='*')  # Скрываем пароль
        toggle_button.config(text='Показать')  # Меняем текст кнопки на "Показать"

# Создаем главное окно Tkinter
root = Tk()  # Инициализация главного окна
root.title("SHA-256 хеширование пароля")  # Заголовок окна

# Создаем метку и поле для ввода пароля
prompt_label = Label(root, text="Введите пароль для хеширования:")  # Создаем метку для ввода пароля
prompt_label.pack(pady=5)  # Располагаем метку

# Размечаем поле ввода и кнопку скрытия пароля
password_frame = Frame(root)  # Создаем рамку для поля ввода и кнопки
password_frame.pack(pady=5)  # Располагаем рамку
entry = Entry(password_frame, show='*')  # Поле ввода для пароля с маскировкой символов
entry.pack(side='left')  # Располагаем поле слева внутри рамки
toggle_button = Button(password_frame, text='Показать', command=password_visibility)  # Кнопка для переключения видимости пароля
toggle_button.pack(side='left')  # Располагаем кнопку слева внутри рамки

# Создаем кнопку для запуска функции хеширования
hash_button = Button(root, text="Хешировать", command=show_hash)  # Кнопка для хеширования пароля
hash_button.pack(pady=5)  # Располагаем кнопку

# Поле для копирования хэша
result_var = StringVar()  # Переменная для хранения результата хеширования
result_entry = Entry(root, textvariable=result_var, state='readonly', width=70)  # Поле для отображения хеша
result_entry.pack(pady=5)  # Располагаем поле

# Запускаем главный цикл Tkinter
root.mainloop()  # Запускаем основной цикл обработки событий