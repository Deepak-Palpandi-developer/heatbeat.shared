using System.Text.Json;
using StackExchange.Redis;

namespace HeatBeat.Shared.Helpers.Services;

public interface IRedisCacheService
{
    Task<T?> GetOrSetAsync<T>(string key, Func<Task<T>> factory, TimeSpan expiration = default);
    Task<T?> GetAsync<T>(string key);
    Task SetAsync<T>(string key, T value, TimeSpan? expiration = null);
    Task RemoveAsync(string key);
}

public class RedisCacheService : IRedisCacheService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly IDatabase _database;

    public RedisCacheService(IConnectionMultiplexer redis)
    {
        _redis = redis;
        _database = _redis.GetDatabase();
    }

    public async Task<T?> GetOrSetAsync<T>(string key, Func<Task<T>> factory, TimeSpan expiration = default)
    {
        if (expiration == default)
        {
            expiration = TimeSpan.FromMinutes(10);
        }

        var cachedValue = await GetAsync<T>(key);

        if (cachedValue != null)
        {
            return cachedValue;
        }

        var value = await factory();

        if (value == null)
        {
            return default;
        }

        if (value is System.Collections.IEnumerable enumerable && value is not string)
        {
            var enumerator = enumerable.GetEnumerator();
            if (!enumerator.MoveNext())
            {
                return value;
            }
        }

        await SetAsync(key, value, expiration);
        return value;
    }


    public async Task<T?> GetAsync<T>(string key)
    {
        var value = await _database.StringGetAsync(key);

        if (!value.HasValue)
        {
            return default;
        }
        string stringValue = value.ToString();
        return JsonSerializer.Deserialize<T>(stringValue);
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null)
    {
        var serializedValue = JsonSerializer.Serialize(value);
        if (expiration.HasValue)
        {
            await _database.StringSetAsync(key, serializedValue, expiration.Value);
        }
        else
        {
            await _database.StringSetAsync(key, serializedValue);
        }
    }

    public async Task RemoveAsync(string key)
    {
        await _database.KeyDeleteAsync(key);
    }
}