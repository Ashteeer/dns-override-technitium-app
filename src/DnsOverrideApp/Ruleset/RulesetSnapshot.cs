/*
DNS Override — приложение для Technitium DNS Server.

Снапшот ruleset в памяти: тело файла как byte[] + смещения строк.
Дерево не строится — тело уже отсортировано ботом (решение D5), поиск идёт
бинарным поиском прямо по буферу, без аллокаций на запрос.

Алгоритм поиска — docs/rule-matching.md §2, один в один.
*/

using System;

namespace DnsOverride.Ruleset
{
    /// <summary>Результат поиска правила для QNAME.</summary>
    readonly struct RuleMatch
    {
        public static readonly RuleMatch NotFound = default;

        public RuleMatch(RuleAction action, int targetIndex, int lineIndex, bool isApex)
        {
            Found = true;
            Action = action;
            TargetIndex = targetIndex;
            LineIndex = lineIndex;
            IsApex = isApex;
        }

        public bool Found { get; }

        public RuleAction Action { get; }

        /// <summary>Индекс в targets[]; осмыслен только при <see cref="RuleAction.Override"/>.</summary>
        public int TargetIndex { get; }

        /// <summary>Номер сработавшей строки тела — для логов и SOA в отрицательных ответах.</summary>
        public int LineIndex { get; }

        public bool IsApex { get; }
    }

    sealed class RulesetSnapshot
    {
        #region variables

        readonly byte[] _body;
        readonly int[] _lineStart;             // длина = Count + 1, последний элемент = _body.Length
        readonly int _count;

        #endregion

        #region constructor

        internal RulesetSnapshot(RulesetHeader header, byte[] body, int[] lineStart, int count, DateTime? sourceModifiedUtc, long sourceLength)
        {
            Header = header;
            _body = body;
            _lineStart = lineStart;
            _count = count;
            SourceModifiedUtc = sourceModifiedUtc;
            SourceLength = sourceLength;
        }

        #endregion

        #region public

        /// <summary>
        /// Ищет правило для QNAME: от самого длинного суффикса к короткому,
        /// первое попадание побеждает. Точное совпадение — подходит A, иначе W;
        /// поддомен — только W.
        /// </summary>
        public RuleMatch Match(string qname)
        {
            if (_count == 0)
                return RuleMatch.NotFound;

            Span<byte> reversed = stackalloc byte[DomainKey.MaxNameLength];
            Span<int> prefixLengths = stackalloc int[DomainKey.MaxLabels];

            if (!DomainKey.TryBuildReversed(qname, reversed, prefixLengths, out int labelCount))
                return RuleMatch.NotFound;

            for (int depth = labelCount; depth > 0; depth--)
            {
                ReadOnlySpan<byte> key = reversed.Slice(0, prefixLengths[depth - 1]);
                bool exact = depth == labelCount;

                int line = LowerBound(key);

                while ((line < _count) && GetKey(line).SequenceEqual(key))
                {
                    bool isApex = _body[_lineStart[line]] == (byte)'A';

                    // apex не покрывает поддомены — при неточном совпадении такая строка пропускается
                    if (!isApex || exact)
                    {
                        RuleAction action = _body[_lineStart[line] + 1] == (byte)'O' ? RuleAction.Override : RuleAction.Passthru;

                        return new RuleMatch(action, ParseTargetIndex(line), line, isApex);
                    }

                    line++;
                }
            }

            return RuleMatch.NotFound;
        }

        /// <summary>Домен сработавшего правила в обычном порядке меток — для SOA и логов.</summary>
        public string GetRuleDomain(int lineIndex)
        {
            return DomainKey.Unreverse(GetKey(lineIndex));
        }

        public ReadOnlySpan<byte> GetLine(int index)
        {
            int start = _lineStart[index];

            return _body.AsSpan(start, _lineStart[index + 1] - 1 - start);   // -1: без '\n'
        }

        #endregion

        #region private

        ReadOnlySpan<byte> GetKey(int index)
        {
            ReadOnlySpan<byte> line = GetLine(index);

            return line.Slice(line.IndexOf((byte)' ') + 1);
        }

        int ParseTargetIndex(int lineIndex)
        {
            ReadOnlySpan<byte> line = GetLine(lineIndex);
            int value = 0;

            for (int i = 2; i < line.Length; i++)
            {
                byte b = line[i];

                if (b == (byte)' ')
                    break;

                value = (value * 10) + (b - (byte)'0');
            }

            return value;
        }

        int LowerBound(ReadOnlySpan<byte> key)
        {
            int low = 0;
            int high = _count;

            while (low < high)
            {
                int middle = (int)(((uint)low + (uint)high) >> 1);

                if (GetKey(middle).SequenceCompareTo(key) < 0)
                    low = middle + 1;
                else
                    high = middle;
            }

            return low;
        }

        #endregion

        #region properties

        public RulesetHeader Header { get; }

        public int Count
        { get { return _count; } }

        /// <summary>Оценка занимаемой памяти: тело + индекс смещений.</summary>
        public long SizeBytes
        { get { return _body.LongLength + ((long)_lineStart.Length * sizeof(int)); } }

        public DateTime? SourceModifiedUtc { get; }

        public long SourceLength { get; }

        #endregion
    }
}
