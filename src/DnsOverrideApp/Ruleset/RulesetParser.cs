/*
DNS Override — приложение для Technitium DNS Server.

Разбор и проверка ruleset.dat (docs/ruleset-loading.md §3).

Порядок: сигнатура → заголовок → sha256 и count тела → построчная проверка.
Проверки повторяют tools/check-ruleset.py — валидатор и приложение не должны
разъезжаться. Любая ошибка отвергает файл целиком: приложение не чинит битые
ссылки и не грузит половину правил.
*/

using System;
using System.Security.Cryptography;
using System.Text;

namespace DnsOverride.Ruleset
{
    static class RulesetParser
    {
        #region constants

        /// <summary>Сигнатура формата: !DNSOVR + номер версии тела.</summary>
        public static ReadOnlySpan<byte> Magic => "!DNSOVR1"u8;

        public const int MaxLineLength = 512;
        public const int MaxRDomainLength = 253;
        public const int MaxLabelLength = 63;

        #endregion

        #region public

        public static RulesetSnapshot Parse(byte[] raw, DateTime? sourceModifiedUtc)
        {
            int newLine = Array.IndexOf(raw, (byte)'\n');
            if (newLine < 0)
                throw new RulesetFormatException("файл не содержит ни одной строки.");

            ReadOnlySpan<byte> headerLine = raw.AsSpan(0, newLine);

            if ((headerLine.Length < Magic.Length + 1) || !headerLine.Slice(0, Magic.Length).SequenceEqual(Magic) || (headerLine[Magic.Length] != (byte)' '))
                throw new RulesetFormatException("неизвестная сигнатура: ожидалось '" + Encoding.ASCII.GetString(Magic) + " '.");

            RulesetHeader header = RulesetHeader.Parse(Encoding.UTF8.GetString(headerLine.Slice(Magic.Length + 1)));

            int bodyLength = raw.Length - (newLine + 1);
            byte[] body = new byte[bodyLength];
            Buffer.BlockCopy(raw, newLine + 1, body, 0, bodyLength);

            string actualSha256 = Convert.ToHexStringLower(SHA256.HashData(body));
            if (!string.Equals(actualSha256, header.Sha256, StringComparison.Ordinal))
                throw new RulesetFormatException("sha256 тела не совпал: в заголовке " + header.Sha256 + ", фактический " + actualSha256 + ".");

            if ((bodyLength > 0) && (body[bodyLength - 1] != (byte)'\n'))
                throw new RulesetFormatException("тело не заканчивается переводом строки.");

            int[] lineStart = ScanBody(body, header, out int count);

            if (count != header.Count)
                throw new RulesetFormatException("count не совпал: в заголовке " + header.Count + ", строк " + count + ".");

            return new RulesetSnapshot(header, body, lineStart, count, sourceModifiedUtc, raw.LongLength);
        }

        #endregion

        #region private

        /// <summary>
        /// Один проход по телу: границы строк, формат строки, диапазон targetIndex,
        /// порядок сортировки и дубликаты. Дубликаты ищутся сравнением с предыдущей
        /// строкой — в отсортированном теле они обязаны лежать рядом.
        /// </summary>
        static int[] ScanBody(byte[] body, RulesetHeader header, out int count)
        {
            int estimate = header.Count > 0 ? header.Count + 1 : 1;
            int[] lineStart = new int[estimate];

            count = 0;
            int start = 0;
            int previousKeyStart = -1;
            int previousKeyLength = 0;
            byte previousScope = 0;

            while (start < body.Length)
            {
                int end = Array.IndexOf(body, (byte)'\n', start);
                if (end < 0)
                    throw new RulesetFormatException("строка " + (count + 2) + ": нет завершающего перевода строки.");

                if (count + 1 >= lineStart.Length)
                    Array.Resize(ref lineStart, lineStart.Length * 2);

                lineStart[count] = start;

                ReadOnlySpan<byte> line = body.AsSpan(start, end - start);
                int lineNumber = count + 2;                     // строка 1 — заголовок

                int keyOffset = ValidateLine(line, lineNumber, header.Targets.Length);
                int keyStart = start + keyOffset;
                int keyLength = line.Length - keyOffset;

                if (previousKeyStart >= 0)
                {
                    int order = body.AsSpan(previousKeyStart, previousKeyLength).SequenceCompareTo(body.AsSpan(keyStart, keyLength));

                    if (order > 0)
                        throw new RulesetFormatException("строка " + lineNumber + ": нарушен порядок сортировки тела.");

                    if (order == 0)
                    {
                        if (previousScope == line[0])
                            throw new RulesetFormatException("строка " + lineNumber + ": дубль пары (rdomain, scope).");

                        if (line[0] == (byte)'A')
                            throw new RulesetFormatException("строка " + lineNumber + ": при одинаковом rdomain запись A должна идти перед W.");
                    }
                }

                previousKeyStart = keyStart;
                previousKeyLength = keyLength;
                previousScope = line[0];

                count++;
                start = end + 1;
            }

            if (count + 1 > lineStart.Length)
                Array.Resize(ref lineStart, count + 1);

            lineStart[count] = body.Length;

            return lineStart;
        }

        /// <summary>Проверяет строку правила и возвращает смещение rdomain внутри неё.</summary>
        static int ValidateLine(ReadOnlySpan<byte> line, int lineNumber, int targetCount)
        {
            if (line.Length > MaxLineLength)
                throw new RulesetFormatException("строка " + lineNumber + ": длина " + line.Length + " > " + MaxLineLength + ".");

            if (line.Length < 5)                                // W O 0 ' ' + минимум один байт домена
                throw new RulesetFormatException("строка " + lineNumber + ": слишком короткая.");

            byte scope = line[0];
            if ((scope != (byte)'W') && (scope != (byte)'A'))
                throw new RulesetFormatException("строка " + lineNumber + ": scope должен быть 'W' или 'A'.");

            byte action = line[1];
            if ((action != (byte)'O') && (action != (byte)'P'))
                throw new RulesetFormatException("строка " + lineNumber + ": action должен быть 'O' или 'P'.");

            int i = 2;
            int targetIndex = 0;
            int digits = 0;

            while ((i < line.Length) && (line[i] != (byte)' '))
            {
                byte b = line[i];

                if ((b < (byte)'0') || (b > (byte)'9'))
                    throw new RulesetFormatException("строка " + lineNumber + ": targetIndex не является числом.");

                if ((digits == 1) && (line[2] == (byte)'0'))
                    throw new RulesetFormatException("строка " + lineNumber + ": targetIndex с ведущим нулём.");

                targetIndex = (targetIndex * 10) + (b - (byte)'0');
                digits++;

                if (digits > 3)
                    throw new RulesetFormatException("строка " + lineNumber + ": targetIndex длиннее трёх цифр.");

                i++;
            }

            if ((digits == 0) || (i >= line.Length))
                throw new RulesetFormatException("строка " + lineNumber + ": не найден разделитель '<targetIndex> <rdomain>'.");

            if (action == (byte)'O')
            {
                if (targetIndex >= targetCount)
                    throw new RulesetFormatException("строка " + lineNumber + ": targetIndex " + targetIndex + " вне диапазона targets[0.." + (targetCount - 1) + "].");
            }
            else if (targetIndex != 0)
            {
                throw new RulesetFormatException("строка " + lineNumber + ": при action=P targetIndex должен быть 0.");
            }

            int domainOffset = i + 1;
            ValidateRDomain(line.Slice(domainOffset), lineNumber);

            return domainOffset;
        }

        internal static void ValidateRDomain(ReadOnlySpan<byte> rdomain, int lineNumber)
        {
            if ((rdomain.Length == 0) || (rdomain.Length > MaxRDomainLength))
                throw new RulesetFormatException("строка " + lineNumber + ": длина rdomain вне диапазона 1.." + MaxRDomainLength + ".");

            int labelLength = 0;
            byte previous = 0;

            for (int i = 0; i < rdomain.Length; i++)
            {
                byte b = rdomain[i];

                if (b == (byte)'.')
                {
                    if (labelLength == 0)
                        throw new RulesetFormatException("строка " + lineNumber + ": пустая метка в rdomain.");

                    if (previous == (byte)'-')
                        throw new RulesetFormatException("строка " + lineNumber + ": метка rdomain заканчивается на '-'.");

                    labelLength = 0;
                    previous = b;
                    continue;
                }

                bool allowed = ((b >= (byte)'a') && (b <= (byte)'z')) || ((b >= (byte)'0') && (b <= (byte)'9')) || (b == (byte)'-');
                if (!allowed)
                    throw new RulesetFormatException("строка " + lineNumber + ": недопустимый байт 0x" + b.ToString("x2") + " в rdomain (домены нормализует бот).");

                if ((labelLength == 0) && (b == (byte)'-'))
                    throw new RulesetFormatException("строка " + lineNumber + ": метка rdomain начинается с '-'.");

                labelLength++;
                previous = b;

                if (labelLength > MaxLabelLength)
                    throw new RulesetFormatException("строка " + lineNumber + ": метка rdomain длиннее " + MaxLabelLength + " байт.");
            }

            if (labelLength == 0)
                throw new RulesetFormatException("строка " + lineNumber + ": rdomain заканчивается точкой.");

            if (previous == (byte)'-')
                throw new RulesetFormatException("строка " + lineNumber + ": метка rdomain заканчивается на '-'.");
        }

        #endregion
    }
}
