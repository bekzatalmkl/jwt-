package kz.bekzat.jwt.repository;
import java.util.*;
/** Generic collection repository; persistent entities are handled by JDBC DAO classes. */
public class Repository<T,ID> { private final Map<ID,T> data=new LinkedHashMap<>(); public void save(ID id,T value){data.put(Objects.requireNonNull(id),Objects.requireNonNull(value));} public Optional<T> findById(ID id){return Optional.ofNullable(data.get(id));} public List<T> findAll(){return new ArrayList<>(data.values());} public Set<ID> findAllIds(){return new LinkedHashSet<>(data.keySet());} public boolean delete(ID id){return data.remove(id)!=null;} }
