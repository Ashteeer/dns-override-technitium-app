/*
DNS Override — приложение для Technitium DNS Server.

Значения — из контракта docs/ruleset-format.md. Приложение не изобретает новых:
всё, что не перечислено здесь, приводит к отказу загрузки файла.
*/

namespace DnsOverride.Ruleset
{
    /// <summary>Байт 1 строки правила: <c>O</c> — override, <c>P</c> — passthru.</summary>
    enum RuleAction : byte
    {
        Passthru = 0,
        Override = 1
    }

    /// <summary><c>targets[].mode</c>.</summary>
    enum TargetMode : byte
    {
        Address = 0,
        NxDomain = 1,
        NoData = 2,
        Refused = 3
    }

    /// <summary><c>targets[].rotation</c>.</summary>
    enum AddressRotation : byte
    {
        None = 0,
        RoundRobin = 1,
        Random = 2
    }

    /// <summary>
    /// <c>targets[].emptyFamilyPolicy</c> — запрошено семейство адресов, которого в target нет.
    /// </summary>
    enum EmptyFamilyPolicy : byte
    {
        /// <summary>Пустой NOERROR + SOA. Реальный адрес не утекает.</summary>
        NoData = 0,

        /// <summary>Обычный резолв: приложение возвращает null.</summary>
        Passthru = 1,

        /// <summary>Пустой NOERROR без SOA.</summary>
        Answer = 2
    }

    /// <summary><c>qtypePolicy</c> — действие по типу запрашиваемой записи.</summary>
    enum QtypeAction : byte
    {
        /// <summary>Ответить согласно <c>mode</c> целевого target.</summary>
        Target = 0,

        /// <summary>NOERROR, пустая ANSWER + SOA в AUTHORITY.</summary>
        NoData = 1,

        /// <summary>NXDOMAIN.</summary>
        NxDomain = 2,

        /// <summary>Вернуть null — обычный резолв, даже если правило override.</summary>
        Passthru = 3
    }
}
