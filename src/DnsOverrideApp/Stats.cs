/*
DNS Override — приложение для Technitium DNS Server.

Счётчики для runtime-state.json. Единственное состояние, которое живёт между
перезагрузками ruleset, поэтому считается с момента старта приложения.
*/

using System;
using System.Threading;

namespace DnsOverride
{
    sealed class Stats
    {
        #region variables

        long _queriesTotal;
        long _overridden;
        long _passthru;
        long _nodata;
        long _nxdomain;
        long _refused;

        #endregion

        #region constructor

        public Stats(DateTime sinceUtc)
        {
            SinceUtc = sinceUtc;
        }

        #endregion

        #region public

        public void CountQuery()
        {
            Interlocked.Increment(ref _queriesTotal);
        }

        public void CountOverridden()
        {
            Interlocked.Increment(ref _overridden);
        }

        public void CountPassthru()
        {
            Interlocked.Increment(ref _passthru);
        }

        public void CountNoData()
        {
            Interlocked.Increment(ref _nodata);
        }

        public void CountNxDomain()
        {
            Interlocked.Increment(ref _nxdomain);
        }

        public void CountRefused()
        {
            Interlocked.Increment(ref _refused);
        }

        #endregion

        #region properties

        public DateTime SinceUtc { get; }

        public long QueriesTotal
        { get { return Interlocked.Read(ref _queriesTotal); } }

        public long Overridden
        { get { return Interlocked.Read(ref _overridden); } }

        public long Passthru
        { get { return Interlocked.Read(ref _passthru); } }

        public long NoData
        { get { return Interlocked.Read(ref _nodata); } }

        public long NxDomain
        { get { return Interlocked.Read(ref _nxdomain); } }

        public long Refused
        { get { return Interlocked.Read(ref _refused); } }

        #endregion
    }
}
