namespace Bulwark.Service.Reputation;

/// <summary>
/// 简单令牌桶限流器。桶容量 = 每周期令牌数;以 (周期/容量) 的速率匀速补充。
/// <see cref="WaitAsync"/> 在无令牌时异步等待到下一个令牌可用,从而把请求速率
/// 平滑限制在配额内(如 4/min)。线程安全。
/// </summary>
public sealed class TokenBucket
{
    private readonly int _capacity;
    private readonly TimeSpan _refillInterval; // 每补充 1 个令牌的间隔
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private double _tokens;
    private DateTime _lastRefillUtc;

    public TokenBucket(int tokensPerPeriod, TimeSpan period)
    {
        _capacity = Math.Max(1, tokensPerPeriod);
        _refillInterval = period / _capacity;
        _tokens = _capacity;      // 初始满桶
        _lastRefillUtc = DateTime.UtcNow;
    }

    /// <summary>取一个令牌;不足时异步等待到可用(受 token 取消约束)。</summary>
    public async Task WaitAsync(CancellationToken token = default)
    {
        while (true)
        {
            TimeSpan delay;
            await _mutex.WaitAsync(token);
            try
            {
                Refill();
                if (_tokens >= 1)
                {
                    _tokens -= 1;
                    return;
                }
                // 计算距离下一个令牌还需多久。
                var elapsed = DateTime.UtcNow - _lastRefillUtc;
                delay = _refillInterval - elapsed;
                if (delay < TimeSpan.Zero) delay = TimeSpan.Zero;
            }
            finally { _mutex.Release(); }

            await Task.Delay(delay <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(50) : delay, token);
        }
    }

    private void Refill()
    {
        var now = DateTime.UtcNow;
        var elapsed = now - _lastRefillUtc;
        if (elapsed <= TimeSpan.Zero) return;

        var refill = elapsed.TotalMilliseconds / _refillInterval.TotalMilliseconds;
        if (refill >= 1)
        {
            _tokens = Math.Min(_capacity, _tokens + Math.Floor(refill));
            _lastRefillUtc = now;
        }
    }
}

/// <summary>
/// 每日配额计数器(本地)。跨自然日(UTC)自动重置。
/// 用于在发起请求前就拦掉超过日配额的查询,避免无谓的网络往返。线程安全。
/// </summary>
public sealed class DailyQuota
{
    private readonly int _limit;
    private readonly object _lock = new();
    private int _count;
    private DateTime _dayUtc;

    public DailyQuota(int dailyLimit)
    {
        _limit = Math.Max(1, dailyLimit);
        _dayUtc = DateTime.UtcNow.Date;
    }

    /// <summary>尝试消费一次配额。成功返回 true;当日已用尽返回 false。</summary>
    public bool TryConsume()
    {
        lock (_lock)
        {
            var today = DateTime.UtcNow.Date;
            if (today != _dayUtc)
            {
                _dayUtc = today;
                _count = 0;
            }
            if (_count >= _limit) return false;
            _count++;
            return true;
        }
    }
}
