using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace HeatBeat.Shared.Cache;

public class RedisCache
{
    private readonly IDistributedCache _cache;
    private readonly DistributedCacheEntryOptions _defaultOptions;

    public RedisCache(IDistributedCache cache)
    {
        _cache = cache;
        _defaultOptions = new DistributedCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromSeconds(30));
    }

    public async Task<T?> GetAsync<T>(string table, Func<Task<T>> func,
        object[] keys, TimeSpan? timespan = null)
    {
        return await GetAsync(table, ToKey(keys), func, timespan);
    }

    public async Task<T?> GetAsync<T>(string table, string key,
        Func<Task<T>> func, TimeSpan? timespan = null)
    {
        string cacheKey = $"{table}:{key}";

        var cacheOptions = _defaultOptions;
        if (timespan != null)
        {
            cacheOptions = new DistributedCacheEntryOptions()
                .SetAbsoluteExpiration((TimeSpan)timespan!);
        }

        T? data = default(T);
        var cacheData = await _cache.GetStringAsync(cacheKey);
        if (cacheData == null)
        {
            data = await func();
            cacheData = JsonSerializer.Serialize(data);
            await _cache.SetStringAsync(cacheKey, cacheData, cacheOptions);
        }
        else
        {
            data = JsonSerializer.Deserialize<T>(cacheData);
        }
        return data;
    }

    public async Task RemoveAsync(string table, string key)
    {
        string cacheKey = $"{table}:{key}";
        var cacheData = await _cache.GetStringAsync(cacheKey);
        if (cacheData != null)
        {
            await _cache.RemoveAsync(cacheKey);
        }
    }
    public string ToKey(params object[] keys)
    {
        return string.Join(":", keys);
    }
    public static string ToKeyV2(params object[] keys)
    {
        return string.Join(":", keys);
    }
}