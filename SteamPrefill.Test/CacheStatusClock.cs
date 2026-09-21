namespace SteamPrefill.Test;

internal sealed class CacheStatusClock : TimeProvider
{
    private readonly object _sync = new();
    private readonly List<ScheduledTimer> _timers = new();
    private DateTimeOffset _utcNow;

    public CacheStatusClock(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    public override DateTimeOffset GetUtcNow()
    {
        lock (_sync)
            return _utcNow;
    }

    public override long GetTimestamp()
    {
        lock (_sync)
            return _utcNow.UtcDateTime.Ticks;
    }

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback,
        object? state,
        TimeSpan dueTime,
        TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);
        var timer = new ScheduledTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    public void Advance(TimeSpan elapsed)
    {
        if (elapsed < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(elapsed));

        lock (_sync)
            _utcNow += elapsed;

        while (true)
        {
            ScheduledTimer? timer;
            lock (_sync)
            {
                timer = _timers
                    .Where(candidate => candidate.DueAtUtc.HasValue && candidate.DueAtUtc <= _utcNow)
                    .OrderBy(candidate => candidate.DueAtUtc)
                    .FirstOrDefault();
                timer?.MarkFired();
            }

            if (timer == null)
                return;
            timer.Invoke();
        }
    }

    private void Change(ScheduledTimer timer, TimeSpan dueTime, TimeSpan period)
    {
        if (dueTime < TimeSpan.Zero && dueTime != Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(nameof(dueTime));
        if (period < TimeSpan.Zero && period != Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(nameof(period));

        lock (_sync)
        {
            if (timer.Disposed)
                throw new ObjectDisposedException(nameof(ScheduledTimer));
            if (!_timers.Contains(timer))
                _timers.Add(timer);
            timer.DueAtUtc = dueTime == Timeout.InfiniteTimeSpan ? null : _utcNow + dueTime;
            timer.Period = period;
        }
    }

    private void Dispose(ScheduledTimer timer)
    {
        lock (_sync)
        {
            timer.Disposed = true;
            timer.DueAtUtc = null;
            _timers.Remove(timer);
        }
    }

    private sealed class ScheduledTimer : ITimer
    {
        private readonly CacheStatusClock _clock;
        private readonly TimerCallback _callback;
        private readonly object? _state;

        public ScheduledTimer(CacheStatusClock clock, TimerCallback callback, object? state)
        {
            _clock = clock;
            _callback = callback;
            _state = state;
        }

        public DateTimeOffset? DueAtUtc { get; set; }
        public TimeSpan Period { get; set; }
        public bool Disposed { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            _clock.Change(this, dueTime, period);
            return true;
        }

        public void Dispose()
        {
            _clock.Dispose(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        public void MarkFired()
        {
            DueAtUtc = Period == Timeout.InfiniteTimeSpan || Period == TimeSpan.Zero
                ? null
                : DueAtUtc + Period;
        }

        public void Invoke()
        {
            if (!Disposed)
                _callback(_state);
        }
    }
}
