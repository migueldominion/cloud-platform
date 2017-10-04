package codes.monkey.bootauth.persistence.dao;

import codes.monkey.bootauth.persistence.model.Privilege;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {

	Privilege findByName(String name);

	@Override
	void delete(Privilege privilege);

}
