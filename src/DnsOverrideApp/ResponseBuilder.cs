/*
DNS Override — приложение для Technitium DNS Server.

Формирование ответа по победившему правилу (docs/rule-matching.md §5).

Флаги: AA = true (приложение отвечает как авторитативная зона),
AD = false всегда — подменённые данные не валидированы, RRSIG не выдаётся.
*/

using System.Collections.Generic;
using DnsOverride.Ruleset;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride
{
    /// <summary>Чем закончилась подмена — для счётчиков в runtime-state.</summary>
    enum ResponseKind : byte
    {
        Passthru = 0,
        Overridden = 1,
        NoData = 2,
        NxDomain = 3,
        Refused = 4
    }

    static class ResponseBuilder
    {
        #region public

        /// <summary>
        /// Строит ответ для запроса, попавшего под правило override.
        /// Возвращает null — passthru: Technitium резолвит запрос обычным путём.
        /// </summary>
        /// <param name="zone">Зона сработавшего правила — владелец SOA в отрицательных ответах.</param>
        public static DnsDatagram? Build(DnsDatagram request, bool isRecursionAllowed, ushort udpPayloadSize, DnsSOARecordData soaRecord, TargetSpec target, QtypeAction policy, ZoneName zone, out ResponseKind kind)
        {
            DnsQuestionRecord question = request.Question[0];

            switch (policy)
            {
                case QtypeAction.Passthru:
                    kind = ResponseKind.Passthru;
                    return null;

                case QtypeAction.NoData:
                    kind = ResponseKind.NoData;
                    return NoData(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);

                case QtypeAction.NxDomain:
                    kind = ResponseKind.NxDomain;
                    return NxDomain(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);
            }

            switch (target.Mode)
            {
                case TargetMode.NxDomain:
                    kind = ResponseKind.NxDomain;
                    return NxDomain(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);

                case TargetMode.NoData:
                    kind = ResponseKind.NoData;
                    return NoData(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);

                case TargetMode.Refused:
                    kind = ResponseKind.Refused;
                    return Create(request, isRecursionAllowed, udpPayloadSize, DnsResponseCode.Refused, null, null);
            }

            // mode = address
            if ((question.Type != DnsResourceRecordType.A) && (question.Type != DnsResourceRecordType.AAAA))
            {
                // qtypePolicy явно потребовал target для типа, для которого у address-target
                // нет данных: отдаём пустой NOERROR, чтобы реальный ответ не утёк.
                kind = ResponseKind.NoData;
                return NoData(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);
            }

            List<DnsResourceRecord> answer = new List<DnsResourceRecord>(4);

            if (target.TryAppendAddresses(answer, question.Name, question.Class, question.Type))
            {
                kind = ResponseKind.Overridden;
                return Create(request, isRecursionAllowed, udpPayloadSize, DnsResponseCode.NoError, answer, null);
            }

            switch (target.EmptyFamilyPolicy)
            {
                case EmptyFamilyPolicy.Passthru:
                    kind = ResponseKind.Passthru;
                    return null;

                case EmptyFamilyPolicy.Answer:
                    kind = ResponseKind.NoData;
                    return Create(request, isRecursionAllowed, udpPayloadSize, DnsResponseCode.NoError, null, null);

                default:
                    kind = ResponseKind.NoData;
                    return NoData(request, isRecursionAllowed, udpPayloadSize, soaRecord, target.Ttl, zone);
            }
        }

        #endregion

        #region private

        /// <summary>NOERROR, пустая ANSWER, SOA зоны правила в AUTHORITY.</summary>
        static DnsDatagram NoData(DnsDatagram request, bool isRecursionAllowed, ushort udpPayloadSize, DnsSOARecordData soaRecord, uint ttl, ZoneName zone)
        {
            DnsQuestionRecord question = request.Question[0];
            DnsResourceRecord[] authority = [new DnsResourceRecord(zone.Value, DnsResourceRecordType.SOA, question.Class, ttl, soaRecord)];

            return Create(request, isRecursionAllowed, udpPayloadSize, DnsResponseCode.NoError, null, authority);
        }

        /// <summary>NXDOMAIN; владелец SOA — родительская зона, как у штатных приложений Technitium.</summary>
        static DnsDatagram NxDomain(DnsDatagram request, bool isRecursionAllowed, ushort udpPayloadSize, DnsSOARecordData soaRecord, uint ttl, ZoneName zone)
        {
            DnsQuestionRecord question = request.Question[0];
            DnsResourceRecord[] authority = [new DnsResourceRecord(DomainKey.ParentZone(zone.Value), DnsResourceRecordType.SOA, question.Class, ttl, soaRecord)];

            return Create(request, isRecursionAllowed, udpPayloadSize, DnsResponseCode.NxDomain, null, authority);
        }

        static DnsDatagram Create(DnsDatagram request, bool isRecursionAllowed, ushort udpPayloadSize, DnsResponseCode rcode, IReadOnlyList<DnsResourceRecord>? answer, IReadOnlyList<DnsResourceRecord>? authority)
        {
            return new DnsDatagram(
                request.Identifier,
                true,                                   // isResponse
                DnsOpcode.StandardQuery,
                true,                                   // authoritativeAnswer
                false,                                  // truncation
                request.RecursionDesired,
                isRecursionAllowed,
                false,                                  // authenticData: подменённые данные не валидированы
                request.CheckingDisabled,
                rcode,
                request.Question,
                answer,
                authority,
                null,
                request.EDNS is null ? ushort.MinValue : udpPayloadSize,
                EDnsHeaderFlags.None,
                null);
        }

        #endregion
    }
}
