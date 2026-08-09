/*
DNS Override — приложение для Technitium DNS Server.
*/

using System;

namespace DnsOverride.Ruleset
{
    /// <summary>
    /// Файл ruleset.dat не соответствует контракту (docs/ruleset-format.md).
    /// Любое такое исключение означает: загрузка отклонена целиком, продолжает
    /// работать предыдущий снапшот (docs/ruleset-loading.md §4).
    /// </summary>
    sealed class RulesetFormatException : Exception
    {
        public RulesetFormatException(string message)
            : base(message)
        { }
    }
}
