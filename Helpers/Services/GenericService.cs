using System.Linq.Expressions;
using AutoMapper;
using HeatBeat.Shared.Helpers.Repositories;

namespace HeatBeat.Shared.Helpers.Services;

public interface IGenericService<TEntity, TDto> where TEntity : class where TDto : class
{
    Task<TDto?> GetByIdAsync(Guid id);
    Task<IEnumerable<TDto>> GetAllAsync();
    Task<IEnumerable<TDto>> FindAsync(Expression<Func<TEntity, bool>> predicate);
    Task<TDto> CreateAsync(TDto dto);
    Task<TDto> UpdateAsync(TDto dto);
    Task DeleteAsync(Guid id);
}

public class GenericService<TEntity, TDto> where TEntity : class where TDto : class
{
    protected readonly IGenericRepository<TEntity> _repository;
    protected readonly IMapper _mapper;

    public GenericService(IGenericRepository<TEntity> repository, IMapper mapper)
    {
        _repository = repository;
        _mapper = mapper;
    }

    public virtual async Task<TDto?> GetByIdAsync(Guid id)
    {
        var entity = await _repository.GetByIdAsync(id);
        return entity == null ? null : _mapper.Map<TDto>(entity);
    }

    public virtual async Task<IEnumerable<TDto>> GetAllAsync()
    {
        var entities = await _repository.GetAllAsync();
        return _mapper.Map<IEnumerable<TDto>>(entities);
    }

    public virtual async Task<IEnumerable<TDto>> FindAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var entities = await _repository.FindAsync(predicate);
        return _mapper.Map<IEnumerable<TDto>>(entities);
    }

    public virtual async Task<TDto> CreateAsync(TDto dto)
    {
        var entity = _mapper.Map<TEntity>(dto);
        await _repository.AddAsync(entity);
        await _repository.SaveChangesAsync();
        return _mapper.Map<TDto>(entity);
    }

    public virtual async Task<TDto> UpdateAsync(TDto dto)
    {
        var entity = _mapper.Map<TEntity>(dto);
        _repository.Update(entity);
        await _repository.SaveChangesAsync();
        return _mapper.Map<TDto>(entity);
    }

    public virtual async Task DeleteAsync(Guid id)
    {
        var entity = await _repository.GetByIdAsync(id);
        if (entity != null)
        {
            _repository.Remove(entity);
            await _repository.SaveChangesAsync();
        }
    }
}
