package kz.bekzat.jwt;
import kz.bekzat.jwt.model.*;import kz.bekzat.jwt.repository.Repository;import kz.bekzat.jwt.service.*;import org.junit.jupiter.api.Test;import static org.junit.jupiter.api.Assertions.*;
class ProjectTests {
 @Test void genericRepositorySavesAndFinds(){var r=new Repository<String,Integer>();r.save(1,"one");assertEquals("one",r.findById(1).orElseThrow());}
 @Test void genericRepositoryListsItems(){var r=new Repository<String,Integer>();r.save(1,"a");r.save(2,"b");assertEquals(2,r.findAll().size());}
 @Test void genericRepositoryDeletes(){var r=new Repository<String,Integer>();r.save(1,"a");assertTrue(r.delete(1));}
 @Test void adminInheritsFromUser(){assertTrue(new Admin("admin","hash") instanceof AppUser);}
 @Test void adminOverridesEntityType(){BaseEntity e=new Admin("admin","hash");assertEquals("ADMIN",e.getEntityType());}
 @Test void roleEnumContainsAdmin(){assertEquals(Role.ADMIN,Role.valueOf("ADMIN"));}
 @Test void tokenStatusHasActive(){assertEquals(TokenStatus.ACTIVE,TokenStatus.valueOf("ACTIVE"));}
 @Test void refreshHashStable(){assertEquals(RefreshTokenService.hash("abc"),RefreshTokenService.hash("abc"));}
 @Test void refreshHashDifferent(){assertNotEquals(RefreshTokenService.hash("abc"),RefreshTokenService.hash("xyz"));}
 @Test void refreshHashIsSha256Length(){assertEquals(64,RefreshTokenService.hash("secret").length());}
 @Test void userRoleIsCorrect(){assertEquals(Role.USER,new AppUser("u","hash",Role.USER).getRole());}
 @Test void entityHasCreatedAt(){assertNotNull(new AppUser("u","hash",Role.USER).getCreatedAt());}
}
