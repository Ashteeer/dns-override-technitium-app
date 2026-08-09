/*
DNS Override — приложение для Technitium DNS Server.

QNAME → rdomain (метки в обратном порядке) в стековом буфере, без аллокаций.

Нормализацию доменов делает бот при компиляции (docs/rule-matching.md §4.2).
Приложение приводит QNAME только к нижнему регистру: имена в DnsDatagram уже
ASCII — TechnitiumLibrary декодирует метки через Encoding.ASCII, поэтому
punycode-преобразование на этом этапе не нужно и невозможно.
*/

using System;

namespace DnsOverride.Ruleset
{
    static class DomainKey
    {
        /// <summary>Максимум байт в доменном имени без завершающей точки.</summary>
        public const int MaxNameLength = 255;

        /// <summary>Верхняя граница числа меток в имени длиной MaxNameLength.</summary>
        public const int MaxLabels = 128;

        /// <summary>
        /// Складывает в <paramref name="destination"/> имя с метками в обратном
        /// порядке (<c>test.google.com</c> → <c>com.google.test</c>) в нижнем регистре.
        /// </summary>
        /// <param name="qname">QNAME из запроса; завершающая точка допускается.</param>
        /// <param name="destination">Буфер не меньше <see cref="MaxNameLength"/> байт.</param>
        /// <param name="prefixLengths">
        /// Буфер не меньше <see cref="MaxLabels"/> элементов. После вызова
        /// <c>prefixLengths[d - 1]</c> — длина префикса из d меток, то есть ключ
        /// для суффикса запроса глубины d.
        /// </param>
        /// <param name="labelCount">Число меток в имени.</param>
        /// <returns>false — имя не может быть ключом (корень, слишком длинное, не ASCII).</returns>
        public static bool TryBuildReversed(string qname, Span<byte> destination, Span<int> prefixLengths, out int labelCount)
        {
            labelCount = 0;

            if (qname is null)
                return false;

            int end = qname.Length;

            if ((end > 0) && (qname[end - 1] == '.'))
                end--;                                  // корневая точка — не метка

            if ((end == 0) || (end > MaxNameLength) || (end > destination.Length))
                return false;

            Span<int> labelStart = stackalloc int[MaxLabels];
            Span<int> labelLength = stackalloc int[MaxLabels];

            int start = 0;

            for (int i = 0; i <= end; i++)
            {
                if ((i == end) || (qname[i] == '.'))
                {
                    if (labelCount == MaxLabels)
                        return false;

                    labelStart[labelCount] = start;
                    labelLength[labelCount] = i - start;
                    labelCount++;
                    start = i + 1;
                }
            }

            if (labelCount > prefixLengths.Length)
                return false;

            int position = 0;

            for (int label = labelCount - 1; label >= 0; label--)
            {
                int from = labelStart[label];
                int length = labelLength[label];

                for (int i = 0; i < length; i++)
                {
                    char c = qname[from + i];

                    if (c > 127)
                        return false;                   // на проводе имена ASCII; иное не совпадёт ни с одним правилом

                    if ((c >= 'A') && (c <= 'Z'))
                        c = (char)(c + 32);

                    destination[position++] = (byte)c;
                }

                prefixLengths[labelCount - label - 1] = position;

                if (label > 0)
                    destination[position++] = (byte)'.';
            }

            return true;
        }

        /// <summary>
        /// rdomain → обычный домен: <c>com.google</c> → <c>google.com</c>.
        /// Нужно только для SOA в отрицательных ответах и для логов совпадений.
        /// </summary>
        public static string Unreverse(ReadOnlySpan<byte> rdomain)
        {
            Span<char> buffer = rdomain.Length <= MaxNameLength ? stackalloc char[rdomain.Length] : new char[rdomain.Length];

            int write = 0;
            int end = rdomain.Length;

            for (int i = rdomain.Length - 1; i >= -1; i--)
            {
                if ((i < 0) || (rdomain[i] == (byte)'.'))
                {
                    for (int j = i + 1; j < end; j++)
                        buffer[write++] = (char)rdomain[j];

                    if (i > 0)
                        buffer[write++] = '.';

                    end = i;
                }
            }

            return new string(buffer.Slice(0, write));
        }

        /// <summary>Родительская зона: <c>www.google.com</c> → <c>google.com</c>, TLD → корень.</summary>
        public static string ParentZone(string domain)
        {
            int i = domain.IndexOf('.');

            return i < 0 ? string.Empty : domain.Substring(i + 1);
        }
    }
}
