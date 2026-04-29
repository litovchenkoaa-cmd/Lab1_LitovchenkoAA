using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UserRegistrationValidator
{
    public static class RegistrationValidator
    {
        private static string EscapeForCharClass(string chars)
        {
            // Порядок важен: сначала обрабатываем обратный слэш
            return chars
                .Replace(@"\", @"\\")  // Экранируем обратный слэш
                .Replace("]", @"\]")   // Закрывающая квадратная скобка
                .Replace("^", @"\^")   // Каретка (если не в начале класса)
                .Replace("-", @"\-");  // Дефис (чтобы не создал диапазон)
        }
        // Запрещённые логины (регистронезависимые)
        private static readonly HashSet<string> ForbiddenLogins = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            "admin", "root", "moderator", "support", "administrator",
            "user", "test", "guest", "anonymous", "system"
        };

        // Допустимые спецсимволы для пароля
        private const string SpecialChars = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?";

        /// <summary>
        /// Проверяет данные регистрации. Возвращает (true, "") в случае успеха,
        /// иначе (false, сообщение об ошибке).
        /// </summary>
        public static (bool Success, string Message) Validate(
            string login, string password, string confirmPassword)
        {
            // 1. Логин не может быть null или пустым
            if (string.IsNullOrEmpty(login))
                return (false, "Логин не может быть пустым.");

            // Определяем тип логина и проверяем формат
            if (IsPhoneFormat(login))
            {
                if (!Regex.IsMatch(login, @"^\+\d-\d{3}-\d{3}-\d{4}$"))
                    return (false, "Неверный формат телефона. Ожидается +X-XXX-XXX-XXXX.");
            }
            else if (IsEmailFormat(login))
            {
                // Простая, но достаточная проверка email
                if (!Regex.IsMatch(login,
                        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
                    return (false, "Неверный формат электронной почты.");
            }
            else // строковый логин
            {
                if (login.Length < 5)
                    return (false, "Логин должен содержать минимум 5 символов.");
                if (!Regex.IsMatch(login, @"^[a-zA-Z0-9_]+$"))
                    return (false,
                        "Логин может содержать только латинские буквы, цифры и знак подчёркивания.");
            }

            // 2. Проверка на запрещённый логин
            if (ForbiddenLogins.Contains(login))
                return (false, "Данный логин запрещён к использованию.");

            // 3. Проверка пароля
            if (string.IsNullOrEmpty(password))
                return (false, "Пароль не может быть пустым.");

            if (password.Length < 7)
                return (false, "Пароль должен содержать минимум 7 символов.");

            // Допустимые символы: кириллица, цифры, спецсимволы
            // Формируем экранированную версию для использования в [...]
            string specialCharsEscaped = EscapeForCharClass(SpecialChars);

            // 1. Проверка: пароль содержит только разрешённые символы
            string allowedPwdPattern = $"^[А-ЯЁа-яё\\d{specialCharsEscaped}]+$";
            if (!Regex.IsMatch(password, allowedPwdPattern))
                return (false,
                    $"Пароль может содержать только кириллические буквы, цифры и спецсимволы ({SpecialChars}).");

            if (!Regex.IsMatch(password, "[А-ЯЁ]"))
                return (false, "Пароль должен содержать хотя бы одну заглавную кириллическую букву.");

            if (!Regex.IsMatch(password, "[а-яё]"))
                return (false, "Пароль должен содержать хотя бы одну строчную кириллическую букву.");

            if (!Regex.IsMatch(password, @"\d"))
                return (false, "Пароль должен содержать хотя бы одну цифру.");

            string escapedSpecials = Regex.Escape(SpecialChars);
            if (!Regex.IsMatch(password, $"[{specialCharsEscaped}]"))
                return (false, "Пароль должен содержать хотя бы один спецсимвол.");

            // 4. Подтверждение пароля
            if (password != confirmPassword)
                return (false, "Пароль и подтверждение не совпадают.");

            return (true, "");
        }

        private static bool IsPhoneFormat(string s)
        {
            // Простейшая проверка: начинается с '+' и содержит дефисы
            return s.StartsWith("+") && s.Contains("-");
        }

        private static bool IsEmailFormat(string s)
        {
            // Содержит '@' и '.' после него
            return s.Contains("@") && s.LastIndexOf('.') > s.IndexOf('@');
        }
    }

    // Маскирование пароля (детерминированное)
    public static class PasswordMasker
    {
        public static string Mask(string password)
        {
            if (password == null) return "****NULL****";
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                // Берём первые 4 байта, преобразуем в 8 шестнадцатеричных символов
                string hex = BitConverter.ToString(hash, 0, 4).Replace("-", "");
                return "****" + hex + "****";
            }
        }
    }

    // Логирование в консоль и файл
    public static class Logger
    {
        private static readonly string LogFilePath = "registration.log";
        private static readonly object fileLock = new object();

        public static void LogSuccess(string login, string maskedPassword, string maskedConfirm)
        {
            string message = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | Успешная регистрация. " +
                             $"Логин: {login}, Пароль: {maskedPassword}, Подтверждение: {maskedConfirm}";
            WriteLog(message);
        }

        public static void LogFailure(string login, string maskedPassword, string maskedConfirm,
            string error, Exception ex = null)
        {
            string stackTrace = ex != null ? $"\nStackTrace: {ex}" : "";
            string message = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | Ошибка регистрации. " +
                             $"Логин: {login}, Пароль: {maskedPassword}, Подтверждение: {maskedConfirm}, " +
                             $"Причина: {error}{stackTrace}";
            WriteLog(message);
        }

        private static void WriteLog(string message)
        {
            // Консоль
            Console.WriteLine(message);
            // Файл
            lock (fileLock)
            {
                try
                {
                    File.AppendAllText(LogFilePath, message + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка записи в лог-файл: {ex.Message}");
                }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Тестовые сценарии (можно заменить на ввод с консоли)
            var testCases = new[]
            {
                // Успешные случаи
                ("valid_user", "Пароль1!", "Пароль1!"),
                ("user_123", "МойПароль2@", "МойПароль2@"),
                ("+7-999-123-4567", "Тест123$", "Тест123$"),
                ("test@mail.ru", "АБВгдеж3#", "АБВгдеж3#"),

                // Ошибки логина
                ("", "pass", "pass"),                       // пустой
                ("abc", "pass", "pass"),                    // короткий строковый
                ("user%name", "pass", "pass"),              // запрещённый символ
                ("+7-12-345-6789", "pass", "pass"),         // плохой телефон
                ("bad@email", "pass", "pass"),              // плохой email
                ("admin", "pass", "pass"),                  // запрещённый логин

                // Ошибки пароля
                ("newUser", "", ""),                        // пустой
                ("newUser", "12345", "12345"),              // короткий
                ("newUser", "Password1", "Password1"),      // нет кириллицы
                ("newUser", "пароль", "пароль"),            // нет цифры и спецсимвола
                ("newUser", "Пароль1", "Пароль2"),          // не совпадает подтверждение
                ("newUser", "пароль1!", "пароль1!"),        // нет заглавной
                ("newUser", "ПАРОЛЬ1!", "ПАРОЛЬ1!"),        // нет строчной
                ("newUser", "Пароль!@", "Пароль!@"),        // нет цифры
                ("newUser", "Пароль123", "Пароль123"),      // нет спецсимвола
            };

            foreach (var (login, password, confirm) in testCases)
            {
                Console.WriteLine($"\n=== Проверка: логин='{login}' пароль='{password}' подтверждение='{confirm}' ===");
                var (success, message) = RegistrationValidator.Validate(login, password, confirm);
                string maskedPwd = PasswordMasker.Mask(password);
                string maskedConfirm = PasswordMasker.Mask(confirm);

                if (success)
                {
                    Console.WriteLine("Результат: True");
                    Logger.LogSuccess(login, maskedPwd, maskedConfirm);
                }
                else
                {
                    Console.WriteLine($"Результат: False, ошибка: {message}");
                    Logger.LogFailure(login, maskedPwd, maskedConfirm, message);
                }
            }

            Console.WriteLine("\nВсе тесты завершены. Лог записан в файл registration.log");
            Console.ReadKey();
        }
    }
}