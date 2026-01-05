using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;

namespace HeatBeat.Shared.Helpers.Repositories;

public interface IGenericRepository<T> where T : class
{
    IQueryable<T> GetQueryable(bool asNoTracking = false);
    Task<T?> GetByIdAsync(Guid id, bool asNoTracking = false);
    Task<IEnumerable<T>> GetAllAsync(bool asNoTracking = true);
    Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true);
    Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true);
    Task<bool> AnyAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true);
    Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, bool asNoTracking = true);
    Task<T> AddAsync(T entity);
    Task AddRangeAsync(IEnumerable<T> entities);
    void Update(T entity);
    void UpdateRange(IEnumerable<T> entities);
    void Remove(T entity);
    void RemoveRange(IEnumerable<T> entities);
    Task<int> SaveChangesAsync();
}

public class GenericRepository<T> : IGenericRepository<T>
    where T : class
{
    protected readonly DbContext _context;
    protected readonly DbSet<T> _dbSet;

    public GenericRepository(DbContext context)
    {
        _context = context;
        _dbSet = context.Set<T>();
    }

    #region QUERY OPERATIONS
    public IQueryable<T> GetQueryable(bool asNoTracking = false)
    {
        return asNoTracking ? _dbSet.AsNoTracking() : _dbSet.AsQueryable();
    }

    public async Task<T?> GetByIdAsync(Guid id, bool asNoTracking = false)
    {
        var entity = await _dbSet.FindAsync(id);

        if (entity != null && asNoTracking)
        {
            _context.Entry(entity).State = EntityState.Detached;
        }

        return entity;
    }

    public async Task<IEnumerable<T>> GetAllAsync(bool asNoTracking = true)
    {
        var query = asNoTracking ? _dbSet.AsNoTracking() : _dbSet;
        return await query.ToListAsync();
    }

    public async Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true)
    {
        var query = asNoTracking ? _dbSet.AsNoTracking() : _dbSet;
        return await query.Where(predicate).ToListAsync();
    }

    public async Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true)
    {
        var query = asNoTracking ? _dbSet.AsNoTracking() : _dbSet;
        return await query.FirstOrDefaultAsync(predicate);
    }

    public async Task<bool> AnyAsync(Expression<Func<T, bool>> predicate, bool asNoTracking = true)
    {
        var query = asNoTracking ? _dbSet.AsNoTracking() : _dbSet;
        return await query.AnyAsync(predicate);
    }

    public async Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, bool asNoTracking = true)
    {
        var query = asNoTracking ? _dbSet.AsNoTracking() : _dbSet;

        if (predicate == null)
            return await query.CountAsync();

        return await query.CountAsync(predicate);
    }

    #endregion

    #region CREATE OPERATIONS

    public async Task<T> AddAsync(T entity)
    {
        await _dbSet.AddAsync(entity);
        return entity;
    }

    public async Task AddRangeAsync(IEnumerable<T> entities)
    {
        await _dbSet.AddRangeAsync(entities);
    }

    #endregion

    #region UPDATE OPERATIONS
    public void Update(T entity)
    {
        _dbSet.Update(entity);
    }

    public void UpdateRange(IEnumerable<T> entities)
    {
        _dbSet.UpdateRange(entities);
    }

    #endregion

    #region DELETE OPERATIONS

    public void Remove(T entity)
    {
        _dbSet.Remove(entity);
    }

    public void RemoveRange(IEnumerable<T> entities)
    {
        _dbSet.RemoveRange(entities);
    }

    #endregion

    #region SAVE OPERATIONS
    public async Task<int> SaveChangesAsync()
    {
        return await _context.SaveChangesAsync();
    }

    #endregion
}