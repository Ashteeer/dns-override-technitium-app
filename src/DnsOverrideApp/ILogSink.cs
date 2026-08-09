/*
DNS Override — приложение для Technitium DNS Server.

Тонкая прослойка над IDnsServer.WriteLog: загрузчик ruleset не должен зависеть
от типов Technitium, иначе его нельзя протестировать без DNS-сервера.
*/

using System;

namespace DnsOverride
{
    interface ILogSink
    {
        void Write(string message);

        void Write(string message, Exception exception);
    }
}
