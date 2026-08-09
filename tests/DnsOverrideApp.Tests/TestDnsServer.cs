/*
Заглушка IDnsServer: приложению нужны только WriteLog, ServerDomain,
ResponsiblePerson, ApplicationFolder и UdpPayloadSize.
*/

using System.Net;
using System.Net.Mail;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsOverride.Tests;

sealed class TestDnsServer : IDnsServer
{
    public readonly List<string> Log = new List<string>();

    public TestDnsServer(string applicationFolder)
    {
        ApplicationFolder = applicationFolder;
    }

    public string ApplicationName => "DNS Override";

    public string ApplicationFolder { get; }

    public string ServerDomain => "dns-test.local";

    public MailAddress ResponsiblePerson => new MailAddress("hostmaster@dns-test.local");

    public IDnsCache DnsCache => throw new NotSupportedException();

    public NetProxy? Proxy => null;

    public IPv6Mode IPv6Mode => IPv6Mode.Disabled;

    public ushort UdpPayloadSize => 1232;

    public void WriteLog(string message)
    {
        lock (Log)
            Log.Add(message);
    }

    public void WriteLog(Exception ex)
    {
        WriteLog(ex.ToString());
    }

    public void WriteLog(string message, Exception ex)
    {
        WriteLog(message + " " + ex);
    }

    public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, IPEndPoint remoteEP, int timeout = 4000, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

sealed class TestLogSink : ILogSink
{
    public readonly List<string> Messages = new List<string>();

    public void Write(string message)
    {
        lock (Messages)
            Messages.Add(message);
    }

    public void Write(string message, Exception exception)
    {
        Write(message + " " + exception.Message);
    }

    public int CountContaining(string fragment)
    {
        lock (Messages)
            return Messages.Count(m => m.Contains(fragment, StringComparison.Ordinal));
    }
}
